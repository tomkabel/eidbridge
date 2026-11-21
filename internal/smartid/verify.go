package smartid

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512" // register SHA-384/512
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"regexp"
	"strings"
	"time"
)

// Callback carries the parameters the Smart-ID app adds to a Web2App
// callback URL. The caller has already checked the browser cookie and the
// bridge's own unpredictable callback value.
type Callback struct {
	SessionSecretDigest   string
	UserChallengeVerifier string
}

// Identity is produced only after every verification step passes. It holds
// what the OIDC layer may need; the certificate itself is not retained.
type Identity struct {
	IDType         string // PNO, PAS or IDC
	Country        string // ISO 3166-1 alpha-2
	Code           string // national identifier; personal data
	GivenName      string
	Surname        string
	DocumentNumber string
	CertLevel      string
	FlowType       string
	NotAfter       time.Time
}

var (
	// OIDs used by the purpose and level checks.
	oidSmartIDAuthEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62306, 5, 7, 0}
	oidSerialNumber   = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidGivenName      = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSurname        = asn1.ObjectIdentifier{2, 5, 4, 4}

	userChallengeRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{43}$`)
	hashByName      = map[string]crypto.Hash{"SHA-256": crypto.SHA256, "SHA-384": crypto.SHA384, "SHA-512": crypto.SHA512}
)

// Verify checks a COMPLETE status against the session that created it and,
// for Web2App, the callback. It follows the pinned response-verification
// order (RESP-VER steps 1–9) and fails closed on the first failed check.
func (c *Client) Verify(s *Session, st *Status, cb *Callback) (*Identity, error) {
	return c.VerifyContext(context.Background(), s, st, cb)
}

// VerifyContext is Verify with a context for the status check.
func (c *Client) VerifyContext(ctx context.Context, s *Session, st *Status, cb *Callback) (*Identity, error) {
	if s == nil || s.rpChallenge == nil {
		return nil, vfail("session destroyed or missing")
	}
	// Step 1: Web2App callback digest.
	if s.Flow == FlowWeb2App {
		if cb == nil {
			return nil, vfail("web2app result without callback")
		}
		if !s.SecretDigestMatches(cb.SessionSecretDigest) {
			return nil, vfail("sessionSecretDigest mismatch")
		}
	}
	// Step 2: state, endResult, protocol and mandatory fields.
	if err := Outcome(st); err != nil {
		return nil, err
	}
	if st.SignatureProtocol != "ACSP_V2" {
		return nil, vfail("signatureProtocol is not ACSP_V2")
	}
	if st.Cert == nil || st.Cert.Value == "" || st.Signature == nil || st.Result.DocumentNumber == "" {
		return nil, vfail("missing cert, signature or documentNumber")
	}
	sig := st.Signature
	if sig.FlowType != s.Flow {
		return nil, vfail("flowType differs from the offered flow")
	}
	if !userChallengeRe.MatchString(sig.UserChallenge) {
		return nil, vfail("malformed userChallenge")
	}
	if len(sig.ServerRandom) < 24 || !b64Re.MatchString(sig.ServerRandom) {
		return nil, vfail("malformed serverRandom")
	}
	if !interactionOffered(s.Interactions, st.InteractionTypeUsed) {
		return nil, vfail("interactionTypeUsed was not offered")
	}
	// Step 3: Web2App user challenge.
	if s.Flow == FlowWeb2App {
		sum := sha256.Sum256([]byte(cb.UserChallengeVerifier))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		if cb.UserChallengeVerifier == "" || subtle.ConstantTimeCompare([]byte(want), []byte(sig.UserChallenge)) != 1 {
			return nil, vfail("userChallengeVerifier mismatch")
		}
	}
	// Step 4: certificate chain to configured CAs only.
	der, err := base64.StdEncoding.DecodeString(st.Cert.Value)
	if err != nil {
		return nil, vfail("cert is not Base64")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, vfail("cert does not parse")
	}
	now := c.cfg.Now()
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: c.cfg.Trust.Roots, Intermediates: c.cfg.Trust.Intermediates,
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil || len(chains) == 0 || len(chains[0]) < 2 {
		return nil, vfail("certificate chain does not verify to a configured CA")
	}
	if leaf.IsCA {
		return nil, vfail("end-entity certificate is a CA")
	}
	// Step 5: Smart-ID scheme policy OIDs.
	for _, want := range c.cfg.PolicyOIDs {
		if !hasPolicy(leaf, want) {
			return nil, vfail("required certificate policy missing")
		}
	}
	// Step 6: purpose.
	if !authPurpose(leaf) {
		return nil, vfail("certificate is not an authentication certificate")
	}
	// Step 7: level, from the response and the certificate content.
	level, ok := authenticationLevel(leaf)
	if !ok || level != st.Cert.CertificateLevel || levelRank(level) < levelRank(c.cfg.MinCertLevel) {
		return nil, vfail("certificate level invalid, mismatched, or below the required minimum")
	}
	// Step 8: identity.
	idType, country, code, ok := ParseSerialNumber(subjectAttr(leaf.Subject, oidSerialNumber))
	if !ok {
		return nil, vfail("subject serialNumber is not PNO/PAS/IDC")
	}
	if s.ExpectedIdentity != "" {
		got := idType + country + "-" + code
		if strings.HasPrefix(s.ExpectedIdentity, idType) && strings.Count(s.ExpectedIdentity, "-") == 1 {
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.ExpectedIdentity)) != 1 {
				return nil, fail(ReasonIdentityMismatch, "certificate identity differs from requested identity")
			}
		} else if subtle.ConstantTimeCompare([]byte(st.Result.DocumentNumber), []byte(s.ExpectedIdentity)) != 1 {
			return nil, fail(ReasonIdentityMismatch, "document number differs from requested document")
		}
	}
	if !strings.HasPrefix(st.Result.DocumentNumber, idType+country+"-"+code+"-") {
		return nil, fail(ReasonIdentityMismatch, "documentNumber does not belong to the certificate subject")
	}
	// Step 9: signature over the rebuilt ACSP_V2 payload.
	if err := c.verifySignature(s, st, leaf); err != nil {
		return nil, err
	}
	// Revocation, after the chain is known; unknown status fails closed.
	issuer := chains[0][1]
	if err := c.cfg.Status.Check(ctx, leaf, issuer); err != nil {
		if err == ErrRevoked {
			return nil, vfail("certificate revoked")
		}
		return nil, &Error{Reason: ReasonStatusUnavailable, Detail: "certificate status unavailable", Cause: err}
	}
	return &Identity{
		IDType: idType, Country: country, Code: code,
		GivenName: subjectAttr(leaf.Subject, oidGivenName), Surname: subjectAttr(leaf.Subject, oidSurname),
		DocumentNumber: st.Result.DocumentNumber, CertLevel: level,
		FlowType: sig.FlowType, NotAfter: leaf.NotAfter,
	}, nil
}

func (c *Client) verifySignature(s *Session, st *Status, leaf *x509.Certificate) error {
	sig := st.Signature
	if sig.SignatureAlgorithm != "rsassa-pss" {
		return vfail("signatureAlgorithm is not rsassa-pss")
	}
	p := sig.Params
	if p == nil || p.MaskGenAlgorithm == nil || p.MaskGenAlgorithm.Parameters == nil || p.SaltLength == nil {
		return vfail("missing RSASSA-PSS parameters")
	}
	h, ok := hashByName[p.HashAlgorithm]
	if !ok {
		return vfail("unsupported hash algorithm")
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
	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 {
		return vfail("certificate key is not RSA-2048 or stronger")
	}
	value, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return vfail("signature value is not Base64")
	}
	msg := ACSPv2Payload(s.scheme, sig.ServerRandom, s.RPChallengeB64(), sig.UserChallenge, s.rpName, "",
		s.Interactions, st.InteractionTypeUsed, s.InitialCallbackURL, sig.FlowType)
	hh := h.New()
	hh.Write(msg)
	if err := rsa.VerifyPSS(pub, h, hh.Sum(nil), value, &rsa.PSSOptions{SaltLength: h.Size(), Hash: h}); err != nil {
		return vfail("signature does not verify")
	}
	return nil
}

// ACSPv2Payload rebuilds the signed authentication data structure
// (SIGPROTO page, pin smartid-rp-api-v3-signature-protocols).
func ACSPv2Payload(scheme, serverRandom, rpChallenge, userChallenge, rpName, brokeredRPName, interactions, interactionTypeUsed, callbackURL, flowType string) []byte {
	ih := sha256.Sum256([]byte(interactions))
	return []byte(strings.Join([]string{scheme, "ACSP_V2", serverRandom, rpChallenge, userChallenge,
		b64(rpName), b64(brokeredRPName), base64.StdEncoding.EncodeToString(ih[:]),
		interactionTypeUsed, callbackURL, flowType}, "|"))
}

// ParseSerialNumber splits an ETSI semantics serialNumber such as
// PNOEE-30001010004. Any other form is rejected.
func ParseSerialNumber(sn string) (idType, country, code string, ok bool) {
	m := semanticsRe.FindStringSubmatch(sn)
	if m == nil || strings.ContainsAny(m[3], " \x00") {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}

func subjectAttr(n pkix.Name, oid asn1.ObjectIdentifier) string {
	for _, a := range n.Names {
		if a.Type.Equal(oid) {
			if s, ok := a.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}

func hasPolicy(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, p := range c.PolicyIdentifiers {
		if p.Equal(oid) {
			return true
		}
	}
	return false
}

// authPurpose accepts the Smart-ID authentication EKU profile or the older
// clientAuth profile (RESP-VER step 6).
func authPurpose(c *x509.Certificate) bool {
	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	for _, u := range c.UnknownExtKeyUsage {
		if u.Equal(oidSmartIDAuthEKU) {
			return true
		}
	}
	const old = x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
	if c.KeyUsage&old != old {
		return false
	}
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

func interactionOffered(interactionsB64, used string) bool {
	b, err := base64.StdEncoding.DecodeString(interactionsB64)
	if err != nil {
		return false
	}
	return used != "" && strings.Contains(string(b), `"type":"`+used+`"`)
}

// DemoPolicyOIDs is the policy observed on demo authentication certificates
// (ADR 0001). It is not SK's designated list; production operators configure
// their own (Q-02).
var DemoPolicyOIDs = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 10015, 17, 2}}
