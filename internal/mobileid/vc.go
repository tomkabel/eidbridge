package mobileid

import "fmt"

// VerificationCode implements MID REST API §2.4.1: the 6 most significant
// bits of the first hash byte followed by the 7 least significant bits of
// the last byte, printed as a 4-digit decimal (0000–8191).
func VerificationCode(hash []byte) string {
	if len(hash) == 0 {
		return ""
	}
	v := int(hash[0]>>2)<<7 | int(hash[len(hash)-1]&0x7f)
	return fmt.Sprintf("%04d", v)
}
