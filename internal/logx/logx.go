// Package logx provides the only logger eidbridge uses. Every record passes
// through RedactingHandler, which masks personal identifiers, certificates,
// signatures, tokens and session secrets at every level, DEBUG included.
// Redaction cannot be disabled.
//
// The primary control is not logging identity data at all: call sites log
// reason codes, route templates and counts. The handler is the backstop.
// Only strings, numbers, booleans, durations, times, errors and values that
// implement slog.LogValuer are rendered; any other value (structs, maps,
// byte slices, pointers) is replaced by its type name.
package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

// New returns a JSON logger writing to w at the given level, wrapped in the
// redacting handler.
func New(w io.Writer, level slog.Leveler) *slog.Logger {
	return slog.New(NewHandler(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})))
}

// NewHandler wraps next so that every message and attribute is redacted.
func NewHandler(next slog.Handler) slog.Handler { return &handler{next: next} }

type handler struct{ next slog.Handler }

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool { return h.next.Enabled(ctx, l) }

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, Redact(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(redactAttr(a))
		return true
	})
	return h.next.Handle(ctx, nr)
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(as))
	for i, a := range as {
		out[i] = redactAttr(a)
	}
	return &handler{next: h.next.WithAttrs(out)}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{next: h.next.WithGroup(Redact(name))}
}

// Personal marks a value that must never be rendered. It always logs as
// "[personal]" so call sites can note that a value existed.
type Personal string

// LogValue implements slog.LogValuer.
func (Personal) LogValue() slog.Value { return slog.StringValue("[personal]") }

const masked = "[redacted]"

func redactAttr(a slog.Attr) slog.Attr {
	if sensitiveKey(a.Key) {
		return slog.String(a.Key, masked)
	}
	return slog.Attr{Key: a.Key, Value: redactValue(a.Value, 0)}
}

func redactValue(v slog.Value, depth int) slog.Value {
	if depth > 8 {
		return slog.StringValue(masked)
	}
	switch v.Kind() {
	case slog.KindString:
		return slog.StringValue(Redact(v.String()))
	case slog.KindInt64, slog.KindUint64, slog.KindFloat64, slog.KindBool, slog.KindDuration, slog.KindTime:
		return v
	case slog.KindGroup:
		as := v.Group()
		out := make([]slog.Attr, len(as))
		for i, a := range as {
			out[i] = redactAttr(a)
			out[i].Value = redactValue(out[i].Value, depth+1)
		}
		return slog.GroupValue(out...)
	case slog.KindLogValuer:
		return redactValue(v.Resolve(), depth+1)
	case slog.KindAny:
		switch x := v.Any().(type) {
		case nil:
			return slog.StringValue("<nil>")
		case error:
			return slog.StringValue(Redact(x.Error()))
		case fmt.Stringer:
			// Stringers are rendered only through the string scanner.
			return slog.StringValue(Redact(x.String()))
		case []byte:
			return slog.StringValue(fmt.Sprintf("[redacted:bytes len=%d]", len(x)))
		default:
			return slog.StringValue(fmt.Sprintf("[redacted:%T]", x))
		}
	}
	return slog.StringValue(masked)
}

var sensitiveKeys = map[string]bool{}

func init() {
	for _, k := range strings.Fields(`secret sessionsecret clientsecret signature sig signaturevalue cert certificate
	certificates certvalue x5c idtoken accesstoken token vptoken refreshtoken code authcode authorizationcode
	codeverifier verifier personalcode idcode identitycode documentnumber semanticsid semanticsidentifier identity
	rpchallenge challenge userchallenge userchallengeverifier serverrandom sessionsecretdigest sessiontoken password
	authorization cookie setcookie givenname familyname surname firstname lastname name phone phonenumber msisdn nonce
	state digest serialnumber subject sub previoussub dateofbirth birthdate presentation disclosure disclosures kbjwt
	webeidtoken authtoken unverifiedcertificate devicelink qr callbackurl`) {
		sensitiveKeys[k] = true
	}
}

func sensitiveKey(k string) bool {
	n := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(k))
	if sensitiveKeys[n] {
		return true
	}
	for _, suf := range []string{"secret", "token", "password", "cert", "signature", "code", "challenge"} {
		if strings.HasSuffix(n, suf) && n != "statuscode" && n != "reasoncode" && n != "errcode" {
			return true
		}
	}
	return false
}

var (
	rePEM       = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(-----END [A-Z0-9 ]+-----|$)`)
	reSemantics = regexp.MustCompile(`\b(PNO|PAS|IDC|TIN|NTR)([A-Z]{2})-[0-9A-Za-z\-]+`)
	reB64       = regexp.MustCompile(`[A-Za-z0-9+/_\-]{32,}={0,2}`)
	rePhone     = regexp.MustCompile(`\+[1-9][0-9]{7,14}`)
	reBareEE    = regexp.MustCompile(`(^|[^0-9])[1-6][0-9]{10}([^0-9]|$)`)
	reLV        = regexp.MustCompile(`(^|[^0-9])[0-9]{6}-?[0-9]{5}([^0-9]|$)`)
)

// Redact masks personal identifiers, PEM blocks, long base64 values and
// phone numbers in s. It is applied to every log message and string value.
func Redact(s string) string {
	if s == "" {
		return s
	}
	s = rePEM.ReplaceAllString(s, "[redacted:pem]")
	s = reSemantics.ReplaceAllString(s, "$1$2-****")
	s = reB64.ReplaceAllStringFunc(s, func(m string) string { return fmt.Sprintf("[redacted:b64 len=%d]", len(m)) })
	s = rePhone.ReplaceAllString(s, "[redacted:phone]")
	// Digit runs: repeat because adjacent matches share a boundary character.
	for i := 0; i < 4 && (reBareEE.MatchString(s) || reLV.MatchString(s)); i++ {
		s = reBareEE.ReplaceAllString(s, "${1}[redacted:idcode]${2}")
		s = reLV.ReplaceAllString(s, "${1}[redacted:idcode]${2}")
	}
	return s
}
