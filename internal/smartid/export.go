package smartid

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// Helpers shared with the RP API v2 package (Story 7.5); same scheme,
// same certificates.

// AuthPurpose reports whether c is a Smart-ID authentication certificate.
func AuthPurpose(c *x509.Certificate) bool { return authPurpose(c) }

// LevelRank orders certificate levels (0 for unknown).
func LevelRank(level string) int { return levelRank(level) }

// AuthenticationLevel derives the level from the certificate's complete,
// unambiguous Smart-ID authentication policy pair.
func AuthenticationLevel(c *x509.Certificate) (string, bool) { return authenticationLevel(c) }

// HasPolicy reports whether c carries the certificate policy oid.
func HasPolicy(c *x509.Certificate, oid asn1.ObjectIdentifier) bool { return hasPolicy(c, oid) }

// SubjectAttr returns the first string value of oid in n.
func SubjectAttr(n pkix.Name, oid asn1.ObjectIdentifier) string { return subjectAttr(n, oid) }
