package smartid

import (
	"crypto/x509"
	"encoding/asn1"
)

// Authentication certificate policy pairs from SK's Certificate and OCSP
// Profile for Smart-ID v4.8, section 2.2.3. Signing uses different policies.
var (
	advancedSchemePolicy  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 10015, 17, 1}
	advancedAuthPolicy    = asn1.ObjectIdentifier{0, 4, 0, 2042, 1, 1}
	qualifiedSchemePolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 10015, 17, 2}
	qualifiedAuthPolicy   = asn1.ObjectIdentifier{0, 4, 0, 2042, 1, 2}
)

func authenticationLevel(cert *x509.Certificate) (string, bool) {
	if cert == nil {
		return "", false
	}
	aScheme, aAuth := hasPolicy(cert, advancedSchemePolicy), hasPolicy(cert, advancedAuthPolicy)
	qScheme, qAuth := hasPolicy(cert, qualifiedSchemePolicy), hasPolicy(cert, qualifiedAuthPolicy)
	switch {
	case aScheme && aAuth && !qScheme && !qAuth:
		return LevelAdvanced, true
	case qScheme && qAuth && !aScheme && !aAuth:
		return LevelQualified, true
	default:
		return "", false
	}
}
