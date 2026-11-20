package web

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/tomkabel/eidbridge/internal/authn"
	"rsc.io/qr"
)

//go:embed i18n/*.json
var i18nFS embed.FS

// Locales in display order. en is the reference catalog.
var Locales = []string{"en", "et", "lv", "lt", "ru"}

var catalogs = map[string]map[string]string{}

func init() {
	for _, l := range Locales {
		b, err := i18nFS.ReadFile(path.Join("i18n", l+".json"))
		if err != nil {
			panic("web: missing catalog " + l)
		}
		m := map[string]string{}
		if err := json.Unmarshal(b, &m); err != nil {
			panic("web: catalog " + l + ": " + err.Error())
		}
		catalogs[l] = m
	}
}

// t returns the message for key in lang, falling back to English.
func t(lang, key string) string {
	if v := catalogs[lang][key]; v != "" {
		return v
	}
	if v := catalogs["en"][key]; v != "" {
		return v
	}
	return key
}

// locale applies ui_locales, then Accept-Language, then the default
// (UX-DR-005).
func (s *Server) locale(r *http.Request, uiLocales []string) string {
	for _, l := range uiLocales {
		if l = primary(l); catalogs[l] != nil {
			return l
		}
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if l := primary(tag); catalogs[l] != nil {
			return l
		}
	}
	return s.cfg.DefaultLocale
}

func primary(tag string) string {
	return strings.ToLower(strings.SplitN(strings.SplitN(tag, "-", 2)[0], "_", 2)[0])
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type localeLink struct {
	Code, Name string
	Current    bool
}

// pageData is the common template model.
func (s *Server) pageData(lang string, f *flow, extra map[string]any) map[string]any {
	d := map[string]any{"Lang": lang, "Demo": s.cfg.Demo, "Base": s.base,
		"T": func(k string) string { return t(lang, k) }}
	var links []localeLink
	for _, l := range Locales {
		links = append(links, localeLink{Code: l, Name: t(l, "locale.name"), Current: l == lang})
	}
	d["Locales"] = links
	if f != nil {
		d["FlowID"] = f.id
		d["FT"] = s.formToken(f)
		d["State"] = f.state
		d["Reason"] = f.reason
		d["Offered"] = f.offered
		d["Method"] = f.method
	}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, f *flow, name string, extra map[string]any) {
	f.mu.Lock()
	lang := f.lang
	d := s.pageData(lang, f, extra)
	if f.state == StatePending && f.pending != nil {
		if ui, err := f.pending.UI(time.Now()); err == nil {
			d["AppLink"] = ui.AppLink
			d["VC"] = ui.VC
			d["Challenge"] = ui.Challenge
			d["HasQR"] = ui.QRPayload != ""
			d["UIExtra"] = ui.Extra
		}
	}
	f.mu.Unlock()
	securityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, d); err != nil {
		http.Error(w, "template error", 500)
		s.cfg.Log.Error("template", "err", err)
		return
	}
	w.Write(buf.Bytes())
}

type methodChoice struct {
	Name     string
	Label    string
	Flows    []string
	Notify   bool
	Selected bool
}

func (s *Server) chooseData(f *flow, r *http.Request) map[string]any {
	return s.chooseDataErr(f, r, "")
}

// chooseDataErr builds the method/flow choice. With one permitted method
// no chooser appears (Story 4.1); login_hint=method:<name> preselects and
// an opt-in remembered method is ignored when no longer enabled.
func (s *Server) chooseDataErr(f *flow, r *http.Request, errKey string) map[string]any {
	f.mu.Lock()
	methods := f.req.Methods
	hint := f.req.LoginHint
	f.mu.Unlock()
	pre := ""
	if name, ok := strings.CutPrefix(hint, "method:"); ok && contains(methods, name) {
		pre = name
	} else if s.cfg.RememberMethod {
		if c, err := r.Cookie("__Host-eidb-method"); err == nil && contains(methods, c.Value) {
			pre = c.Value
		}
	}
	var choices []methodChoice
	for _, name := range methods {
		m, ok := s.cfg.Registry.Get(name)
		if !ok {
			continue
		}
		mc := methodChoice{Name: name, Label: "method." + name, Selected: name == pre}
		for _, fl := range s.offeredFlows(m) {
			if fl == authn.FlowNotification {
				mc.Notify = true
				continue
			}
			mc.Flows = append(mc.Flows, fl)
		}
		choices = append(choices, mc)
	}
	if pre != "" {
		for _, c := range choices {
			if c.Name == pre {
				choices = []methodChoice{c}
				break
			}
		}
	}
	d := map[string]any{"Choices": choices, "Chooser": len(choices) > 1, "Error": errKey, "RememberOffer": s.cfg.RememberMethod && len(choices) > 1}
	return d
}

// qrPNG renders a QR code at medium error correction with a quiet zone.
func qrPNG(payload string) ([]byte, error) {
	code, err := qr.Encode(payload, qr.M)
	if err != nil {
		return nil, err
	}
	const scale, quiet = 6, 4
	size := (code.Size + 2*quiet) * scale
	img := image.NewGray(image.Rect(0, 0, size, size))
	for i := range img.Pix {
		img.Pix[i] = 255
	}
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if code.Black(x, y) {
				for dy := 0; dy < scale; dy++ {
					for dx := 0; dx < scale; dx++ {
						img.SetGray((x+quiet)*scale+dx, (y+quiet)*scale+dy, color.Gray{0})
					}
				}
			}
		}
	}
	var buf bytes.Buffer
	err = png.Encode(&buf, img)
	return buf.Bytes(), err
}
