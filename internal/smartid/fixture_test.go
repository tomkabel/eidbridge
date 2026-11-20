package smartid

import (
	"crypto/rand"
	"encoding/base64"
)

var randRead = rand.Read

type fixtureMeta struct {
	Captured           string `json:"captured"`
	Source             string `json:"source"`
	Flow               string `json:"flow"`
	RPChallenge        string `json:"rpChallenge"`
	Interactions       string `json:"interactions"`
	InitialCallbackURL string `json:"initialCallbackUrl"`
	ExpectedIdentity   string `json:"expectedIdentity,omitempty"`
	SessionSecret      string `json:"sessionSecret,omitempty"`
	SessionToken       string `json:"sessionToken,omitempty"`
	DeviceLinkBase     string `json:"deviceLinkBase,omitempty"`
	CallbackURL        string `json:"callbackUrl,omitempty"`
	VC                 string `json:"vc,omitempty"`
	VerifyReason       string `json:"verifyReason"`
}

func b64std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
