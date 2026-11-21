package revocation

import (
	"testing"

	"golang.org/x/crypto/ocsp"
)

func TestPR31OCSPSignatureParseErrorIsTerminal(t *testing.T) {
	for _, message := range []string{
		"bad OCSP signature: x509: ECDSA verification failure",
		"bad signature on embedded certificate: x509: ECDSA verification failure",
		"unsupported critical extension",
		"no response matching the supplied certificate",
	} {
		if !isOCSPValidationError(ocsp.ParseError(message)) {
			t.Errorf("security validation error classified as malformed transport data: %s", message)
		}
	}
}
