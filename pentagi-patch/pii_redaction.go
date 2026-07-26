// PII REDACTION — CyberTestify yamasi (bkz repo kokundeki PATCHES.md).
//
// Amac: Anthropic'e (ve TUM saglayicilara) giden LLM mesajlarindaki YAPISAL
// kisisel veriyi (email, TR telefon, TCKN, kredi karti no, IBAN), veri ABD'deki
// API'ye ULASMADAN ONCE, kod seviyesinde maskelemek. wrapper.go icindeki iki
// evrensel choke point'te uygulanir: WrapGenerateContent (ana ajan zinciri) ve
// WrapGenerateFromSinglePrompt (tek prompt). Tum saglayicilar bu ikisinden gecer.
//
// SINIR (kalinti risk): Bu regex/checksum tabanli bir yaklasimdir. Yapisal PII'yi
// (email/telefon/TCKN/kart/IBAN) yakalar; serbest metindeki ISIM, ADRES gibi
// verileri YAKALAMAZ. Bu bilinen ve kabul edilen bir sinirdir (NER kapsam disi).
package provider

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/vxcontrol/langchaingo/llms"
)

var (
	reEmail    = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}`)
	rePhoneTR  = regexp.MustCompile(`(?:\+?90[ \-]?|0)5\d{2}[ \-]?\d{3}[ \-]?\d{2}[ \-]?\d{2}`)
	reEleven   = regexp.MustCompile(`\b\d{11}\b`)
	reCardCand = regexp.MustCompile(`\b\d(?:[ \-]?\d){12,18}\b`)
	reIbanTR   = regexp.MustCompile(`(?i)\bTR\d{2}(?:[ ]?\d){22}\b`)
)

// RedactAll, verilen metindeki yapisal PII'yi maskelenmis token'larla degistirir.
func RedactAll(s string) string {
	if s == "" {
		return s
	}
	s = reEmail.ReplaceAllString(s, "[EMAIL_REDACTED]")
	// IBAN ve kart, TCKN'den ONCE (uzun rakam dizileri once ele alinsin).
	s = reIbanTR.ReplaceAllStringFunc(s, func(m string) string {
		if validIBAN(m) {
			return "[IBAN_REDACTED]"
		}
		return m
	})
	s = reCardCand.ReplaceAllStringFunc(s, func(m string) string {
		d := onlyDigits(m)
		if len(d) >= 13 && len(d) <= 19 && luhnValid(d) {
			return "[CARD_REDACTED]"
		}
		return m
	})
	s = reEleven.ReplaceAllStringFunc(s, func(m string) string {
		if validTCKN(m) {
			return "[TCKN_REDACTED]"
		}
		return m
	})
	s = rePhoneTR.ReplaceAllString(s, "[PHONE_REDACTED]")
	return s
}

// RedactMessages, LLM'e gonderilecek mesaj zincirinin metin iceren tum
// parcalarini (metin, tool cagri sonucu, tool cagri argumanlari) maskeler.
func RedactMessages(messages []llms.MessageContent) []llms.MessageContent {
	out := make([]llms.MessageContent, len(messages))
	for i := range messages {
		m := messages[i]
		parts := make([]llms.ContentPart, len(m.Parts))
		for j, p := range m.Parts {
			switch v := p.(type) {
			case llms.TextContent:
				v.Text = RedactAll(v.Text)
				parts[j] = v
			case llms.ToolCallResponse:
				v.Content = RedactAll(v.Content)
				parts[j] = v
			case llms.ToolCall:
				if v.FunctionCall != nil {
					fc := *v.FunctionCall
					fc.Arguments = RedactAll(fc.Arguments)
					v.FunctionCall = &fc
				}
				parts[j] = v
			default:
				parts[j] = p
			}
		}
		out[i] = llms.MessageContent{Role: m.Role, Parts: parts}
	}
	return out
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// luhnValid — kredi karti numarasi Luhn kontrolu.
func luhnValid(s string) bool {
	sum := 0
	alt := false
	for i := len(s) - 1; i >= 0; i-- {
		n := int(s[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return len(s) > 0 && sum%10 == 0
}

// validTCKN — 11 haneli TC Kimlik No'nun resmi checksum kurallari.
func validTCKN(s string) bool {
	if len(s) != 11 || s[0] == '0' {
		return false
	}
	var d [11]int
	for i := 0; i < 11; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		d[i] = int(s[i] - '0')
	}
	odd := d[0] + d[2] + d[4] + d[6] + d[8]
	even := d[1] + d[3] + d[5] + d[7]
	digit10 := (((odd*7 - even) % 10) + 10) % 10
	if digit10 != d[9] {
		return false
	}
	total := 0
	for i := 0; i < 10; i++ {
		total += d[i]
	}
	return total%10 == d[10]
}

// validIBAN — IBAN mod-97 dogrulamasi (yanlis-pozitifi azaltir).
func validIBAN(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearranged := s[4:] + s[:4]
	var digits strings.Builder
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			digits.WriteString(strconv.Itoa(int(r-'A') + 10))
		default:
			return false
		}
	}
	rem := 0
	for _, c := range digits.String() {
		rem = (rem*10 + int(c-'0')) % 97
	}
	return rem == 1
}
