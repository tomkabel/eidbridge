package smartid

import (
	"encoding/json"
	"errors"
	"regexp"
)

// Status is the parsed GET /v3/session/{id} response. Unknown JSON fields
// are ignored as the API requires.
type Status struct {
	State  string `json:"state"`
	Result *struct {
		EndResult      string `json:"endResult"`
		DocumentNumber string `json:"documentNumber"`
		Details        *struct {
			Interaction string `json:"interaction"`
		} `json:"details"`
	} `json:"result"`
	SignatureProtocol string     `json:"signatureProtocol"`
	Signature         *Signature `json:"signature"`
	Cert              *struct {
		Value            string `json:"value"`
		CertificateLevel string `json:"certificateLevel"`
	} `json:"cert"`
	InteractionTypeUsed  string `json:"interactionTypeUsed"`
	DeviceIPAddress      string `json:"deviceIpAddress"`
	DeviceLinkRegistered *bool  `json:"deviceLinkRegistered"`
}

// Signature is the ACSP_V2 signature object.
type Signature struct {
	Value              string `json:"value"`
	ServerRandom       string `json:"serverRandom"`
	UserChallenge      string `json:"userChallenge"`
	FlowType           string `json:"flowType"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	Params             *struct {
		HashAlgorithm    string `json:"hashAlgorithm"`
		MaskGenAlgorithm *struct {
			Algorithm  string `json:"algorithm"`
			Parameters *struct {
				HashAlgorithm string `json:"hashAlgorithm"`
			} `json:"parameters"`
		} `json:"maskGenAlgorithm"`
		SaltLength   *int   `json:"saltLength"`
		TrailerField string `json:"trailerField"`
	} `json:"signatureAlgorithmParameters"`
}

// MaxStatusBody bounds ParseStatus input.
const MaxStatusBody = 64 << 10

// ParseStatus decodes and structurally validates a session status body.
func ParseStatus(b []byte) (*Status, error) {
	if len(b) == 0 || len(b) > MaxStatusBody {
		return nil, fail(ReasonUnknownEndResult, "empty or oversized status body")
	}
	var st Status
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fail(ReasonUnknownEndResult, "malformed status JSON")
	}
	switch st.State {
	case "RUNNING":
		return &st, nil
	case "COMPLETE":
		if st.Result == nil || st.Result.EndResult == "" {
			return nil, fail(ReasonUnknownEndResult, "COMPLETE without endResult")
		}
		return &st, nil
	}
	return nil, fail(ReasonUnknownEndResult, "unknown session state")
}

// Outcome classifies a COMPLETE status before cryptographic verification.
// It returns nil only for endResult OK; any other value maps to a typed
// terminal error per the architecture's endResult table.
func Outcome(st *Status) error {
	if st == nil || st.State != "COMPLETE" || st.Result == nil {
		return fail(ReasonUnknownEndResult, "not a complete status")
	}
	switch st.Result.EndResult {
	case "OK":
		return nil
	case "USER_REFUSED", "USER_REFUSED_CERT_CHOICE", "USER_REFUSED_INTERACTION":
		return fail(ReasonRefused, st.Result.EndResult)
	case "TIMEOUT":
		return fail(ReasonExpired, st.Result.EndResult)
	case "WRONG_VC":
		return fail(ReasonWrongCode, st.Result.EndResult)
	case "DOCUMENT_UNUSABLE", "ACCOUNT_UNUSABLE":
		return fail(ReasonAccountUnusable, st.Result.EndResult)
	case "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP", "PROTOCOL_FAILURE", "EXPECTED_LINKED_SESSION", "SERVER_ERROR":
		return fail(ReasonUpstreamError, st.Result.EndResult)
	}
	return fail(ReasonUnknownEndResult, "unknown endResult")
}

var (
	semanticsRe = regexp.MustCompile(`^(PNO|PAS|IDC)([A-Z]{2})-(.+)$`)
	digitsRe    = regexp.MustCompile(`^[0-9]+$`)
)

// ValidateSemanticsID validates an ETSI natural-person semantics identifier
// locally, before any outbound request. Personal numbers (PNO) for EE, LT and
// LV are checksum-validated; other countries and types are rejected in
// notification mode.
func ValidateSemanticsID(id string) error {
	m := semanticsRe.FindStringSubmatch(id)
	if m == nil || m[1] != "PNO" {
		return errors.New("smartid: identifier must be PNO<country>-<code>")
	}
	if !ValidPersonalCode(m[2], m[3]) {
		return errors.New("smartid: invalid personal code")
	}
	return nil
}

// ValidPersonalCode checks the format and checksum of EE, LT and LV codes.
func ValidPersonalCode(country, code string) bool {
	switch country {
	case "EE", "LT":
		if len(code) != 11 || !digitsRe.MatchString(code) || code[0] < '1' || code[0] > '6' {
			return false
		}
		return eeChecksum(code) == int(code[10]-'0')
	case "LV":
		if len(code) != 12 || code[6] != '-' {
			return false
		}
		d := code[:6] + code[7:]
		if !digitsRe.MatchString(d) {
			return false
		}
		if d[:2] == "32" { // post-2017 codes carry no checksum
			return true
		}
		w := []int{1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
		sum := 0
		for i, x := range w {
			sum += x * int(d[i]-'0')
		}
		return (1101-sum)%11 == int(d[10]-'0')
	}
	return false
}

func eeChecksum(code string) int {
	w1 := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 1}
	w2 := []int{3, 4, 5, 6, 7, 8, 9, 1, 2, 3}
	sum := func(w []int) int {
		s := 0
		for i, x := range w {
			s += x * int(code[i]-'0')
		}
		return s % 11
	}
	if r := sum(w1); r != 10 {
		return r
	}
	if r := sum(w2); r != 10 {
		return r
	}
	return 0
}
