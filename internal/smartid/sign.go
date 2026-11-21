package smartid

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// Signature sessions (Story 8.1, FR-028). The bridge relays a digest that
// the integrator computed and verifies the returned signature; it never sees
// the document and makes no claim about the legal status of the result.
// Written from the pinned RP-API_V3.yml (sha256 bb3e34bd…) and the
// signature protocols page (sha256 3b8c8f2c…): certificate-choice by ETSI
// identifier, then RAW_DIGEST_SIGNATURE by the returned document number.

// SigningCert is a signing certificate that passed VerifyCertificateChoice.
type SigningCert struct {
	Certificate    *x509.Certificate
	DocumentNumber string
	Level          string
	serial         string
	verified       bool
}

// SignRequest describes the digest to sign.
type SignRequest struct {
	Digest             []byte
	HashAlgorithm      string // SHA-256, SHA-384 or SHA-512
	SignatureAlgorithm string // rsassa-pss (recommended) or shaNNNWithRSAEncryption (deprecated)
	DisplayText200     string // shown in the confirmationMessage interaction
}

// SignSession is a running signature session.
type SignSession struct {
	ID           string
	VC           string // verification code the integrator must display
	cert         *SigningCert
	req          SignRequest
	interactions string
}

// SignResult is a verified signature.
type SignResult struct {
	Value              []byte
	SignatureAlgorithm string
	HashAlgorithm      string
	Certificate        *x509.Certificate
	DocumentNumber     string
	Level              string
}

var (
	vcRe       = regexp.MustCompile(`^[0-9]{4}$`)
	pkcs1ByAlg = map[string]string{"sha256WithRSAEncryption": "SHA-256", "sha384WithRSAEncryption": "SHA-384", "sha512WithRSAEncryption": "SHA-512"}
)

// StartCertificateChoice starts a notification certificate-choice session
// for an ETSI semantics identifier and returns its session ID.
func (c *Client) StartCertificateChoice(ctx context.Context, semanticsID string) (string, error) {
	if err := ValidateSemanticsID(semanticsID); err != nil {
		return "", err
	}
	req := map[string]any{"relyingPartyUUID": c.cfg.RPUUID, "relyingPartyName": c.cfg.RPName, "certificateLevel": c.cfg.MinCertLevel}
	var resp struct {
		SessionID string `json:"sessionID"`
	}
	if err := c.post(ctx, "/v3/signature/certificate-choice/notification/etsi/"+url.PathEscape(semanticsID), "create-certificate-choice", req, &resp); err != nil {
		return "", err
	}
	if !uuidRe.MatchString(resp.SessionID) {
		return "", fail(ReasonUpstreamError, "malformed certificate-choice response")
	}
	return resp.SessionID, nil
}

// VerifyCertificateChoice checks a COMPLETE certificate-choice status and
// returns the signing certificate of semanticsID.
func (c *Client) VerifyCertificateChoice(ctx context.Context, semanticsID string, st *Status) (*SigningCert, error) {
	if err := Outcome(st); err != nil {
		return nil, err
	}
	if st.Signature == nil || st.Signature.FlowType != FlowNotification {
		return nil, vfail("flowType differs from the offered flow")
	}
	leaf, issuer, err := c.signingCert(st, semanticsID)
	if err != nil {
		return nil, err
	}
	if err := c.signStatus(ctx, leaf, issuer); err != nil {
		return nil, err
	}
	return &SigningCert{Certificate: leaf, DocumentNumber: st.Result.DocumentNumber, Level: st.Cert.CertificateLevel,
		serial: semanticsID, verified: true}, nil
}

// StartSignature starts a RAW_DIGEST_SIGNATURE notification session for a
// certificate from VerifyCertificateChoice.
func (c *Client) StartSignature(ctx context.Context, sc *SigningCert, r SignRequest) (*SignSession, error) {
	if sc == nil || !sc.verified {
		return nil, errors.New("smartid: signing certificate was not verified")
	}
	h, ok := hashByName[r.HashAlgorithm]
	if !ok || len(r.Digest) != h.Size() {
		return nil, errors.New("smartid: digest does not match the hash algorithm")
	}
	params := map[string]any{"digest": base64.StdEncoding.EncodeToString(r.Digest), "signatureAlgorithm": r.SignatureAlgorithm}
	switch {
	case r.SignatureAlgorithm == "rsassa-pss":
		params["signatureAlgorithmParameters"] = map[string]string{"hashAlgorithm": r.HashAlgorithm}
	case pkcs1ByAlg[r.SignatureAlgorithm] == "":
		return nil, errors.New("smartid: unsupported signature algorithm")
	case pkcs1ByAlg[r.SignatureAlgorithm] != r.HashAlgorithm:
		return nil, errors.New("smartid: signature algorithm and hash differ")
	}
	if r.DisplayText200 == "" || len([]rune(r.DisplayText200)) > 200 {
		return nil, errors.New("smartid: displayText200 must be 1 to 200 characters")
	}
	ib, err := json.Marshal([]map[string]string{{"type": "confirmationMessage", "displayText200": r.DisplayText200}})
	if err != nil {
		return nil, err
	}
	inter := base64.StdEncoding.EncodeToString(ib)
	nonce := make([]byte, 15)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	req := map[string]any{"relyingPartyUUID": c.cfg.RPUUID, "relyingPartyName": c.cfg.RPName, "certificateLevel": c.cfg.MinCertLevel,
		"signatureProtocol": "RAW_DIGEST_SIGNATURE", "signatureProtocolParameters": params,
		"nonce": base64.RawURLEncoding.EncodeToString(nonce), "interactions": inter,
		"requestProperties": map[string]bool{"shareMdClientIpAddress": false}}
	var resp struct {
		SessionID string `json:"sessionID"`
		VC        struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"vc"`
	}
	if err := c.post(ctx, "/v3/signature/notification/document/"+url.PathEscape(sc.DocumentNumber), "create-signature", req, &resp); err != nil {
		return nil, err
	}
	if !uuidRe.MatchString(resp.SessionID) || resp.VC.Type != "numeric4" || !vcRe.MatchString(resp.VC.Value) {
		return nil, fail(ReasonUpstreamError, "malformed signature session response")
	}
	r.Digest = append([]byte(nil), r.Digest...)
	return &SignSession{ID: resp.SessionID, VC: resp.VC.Value, cert: sc, req: r, interactions: inter}, nil
}

// VerifyRawDigest checks a COMPLETE signature status against its session.
func (c *Client) VerifyRawDigest(ctx context.Context, ss *SignSession, st *Status) (*SignResult, error) {
	if ss == nil || ss.cert == nil {
		return nil, vfail("signature session missing")
	}
	if err := Outcome(st); err != nil {
		return nil, err
	}
	if st.SignatureProtocol != "RAW_DIGEST_SIGNATURE" {
		return nil, vfail("signatureProtocol is not RAW_DIGEST_SIGNATURE")
	}
	sig := st.Signature
	if sig == nil || sig.Value == "" {
		return nil, vfail("missing signature")
	}
	if st.Result.DocumentNumber != ss.cert.DocumentNumber {
		return nil, fail(ReasonIdentityMismatch, "document number differs from the chosen document")
	}
	if sig.FlowType != FlowNotification {
		return nil, vfail("flowType differs from the offered flow")
	}
	if !interactionOffered(ss.interactions, st.InteractionTypeUsed) {
		return nil, vfail("interactionTypeUsed was not offered")
	}
	leaf, issuer, err := c.signingCert(st, ss.cert.serial)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(leaf.Raw, ss.cert.Certificate.Raw) {
		return nil, vfail("certificate differs from the chosen signing certificate")
	}
	if err := verifyRawSignature(ss.req, sig, leaf); err != nil {
		return nil, err
	}
	if err := c.signStatus(ctx, leaf, issuer); err != nil {
		return nil, err
	}
	value, _ := base64.StdEncoding.DecodeString(sig.Value)
	return &SignResult{Value: value, SignatureAlgorithm: sig.SignatureAlgorithm, HashAlgorithm: ss.req.HashAlgorithm,
		Certificate: leaf, DocumentNumber: st.Result.DocumentNumber, Level: st.Cert.CertificateLevel}, nil
}

func verifyRawSignature(r SignRequest, sig *Signature, leaf *x509.Certificate) error {
	if sig.SignatureAlgorithm != r.SignatureAlgorithm {
		return vfail("signatureAlgorithm differs from the requested algorithm")
	}
	h := hashByName[r.HashAlgorithm]
	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 {
		return vfail("certificate key is not RSA-2048 or stronger")
	}
	value, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return vfail("signature value is not Base64")
	}
	if r.SignatureAlgorithm != "rsassa-pss" {
		if rsa.VerifyPKCS1v15(pub, h, r.Digest, value) != nil {
			return vfail("signature does not verify")
		}
		return nil
	}
	p := sig.Params
	if p == nil || p.MaskGenAlgorithm == nil || p.MaskGenAlgorithm.Parameters == nil || p.SaltLength == nil {
		return vfail("missing RSASSA-PSS parameters")
	}
	if p.HashAlgorithm != r.HashAlgorithm {
		return vfail("hash algorithm differs from the requested hash")
	}
	if p.MaskGenAlgorithm.Algorithm != "id-mgf1" || p.MaskGenAlgorithm.Parameters.HashAlgorithm != p.HashAlgorithm {
		return vfail("MGF1 must use the signature hash")
	}
	if *p.SaltLength != h.Size() {
		return vfail("salt length must equal hash length")
	}
	if p.TrailerField != "" && p.TrailerField != "0xbc" {
		return vfail("unsupported trailer field")
	}
	if rsa.VerifyPSS(pub, h, r.Digest, value, &rsa.PSSOptions{SaltLength: h.Size(), Hash: h}) != nil {
		return vfail("signature does not verify")
	}
	return nil
}

// signingCert runs the certificate checks shared by both session kinds:
// chain to configured CAs, scheme policy, signing purpose, level, identity.
func (c *Client) signingCert(st *Status, semanticsID string) (leaf, issuer *x509.Certificate, err error) {
	if st.Cert == nil || st.Cert.Value == "" || st.Result.DocumentNumber == "" {
		return nil, nil, vfail("missing cert or documentNumber")
	}
	der, err := base64.StdEncoding.DecodeString(st.Cert.Value)
	if err != nil {
		return nil, nil, vfail("cert is not Base64")
	}
	if leaf, err = x509.ParseCertificate(der); err != nil {
		return nil, nil, vfail("cert does not parse")
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: c.cfg.Trust.Roots, Intermediates: c.cfg.Trust.Intermediates,
		CurrentTime: c.cfg.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil || len(chains) == 0 || len(chains[0]) < 2 {
		return nil, nil, vfail("certificate chain does not verify to a configured CA")
	}
	if leaf.IsCA {
		return nil, nil, vfail("end-entity certificate is a CA")
	}
	for _, want := range c.cfg.PolicyOIDs {
		if !hasPolicy(leaf, want) {
			return nil, nil, vfail("required certificate policy missing")
		}
	}
	if !signingPurpose(leaf) {
		return nil, nil, vfail("certificate is not a signing certificate")
	}
	if levelRank(st.Cert.CertificateLevel) == 0 || levelRank(st.Cert.CertificateLevel) < levelRank(c.cfg.MinCertLevel) {
		return nil, nil, vfail("certificate level below the required minimum")
	}
	idType, country, code, ok := ParseSerialNumber(subjectAttr(leaf.Subject, oidSerialNumber))
	if !ok || idType+country+"-"+code != semanticsID {
		return nil, nil, fail(ReasonIdentityMismatch, "certificate identity differs from the requested signer")
	}
	if !strings.HasPrefix(st.Result.DocumentNumber, semanticsID+"-") {
		return nil, nil, fail(ReasonIdentityMismatch, "documentNumber does not belong to the certificate subject")
	}
	return leaf, chains[0][1], nil
}

// signingPurpose: nonRepudiation (contentCommitment) and not an
// authentication certificate.
func signingPurpose(c *x509.Certificate) bool {
	return c.KeyUsage&x509.KeyUsageContentCommitment != 0 && !authPurpose(c) &&
		c.KeyUsage&x509.KeyUsageDigitalSignature == 0
}

func (c *Client) signStatus(ctx context.Context, leaf, issuer *x509.Certificate) error {
	if err := c.cfg.Status.Check(ctx, leaf, issuer); err != nil {
		if err == ErrRevoked {
			return vfail("certificate revoked")
		}
		return &Error{Reason: ReasonStatusUnavailable, Detail: "certificate status unavailable", Cause: err}
	}
	return nil
}
