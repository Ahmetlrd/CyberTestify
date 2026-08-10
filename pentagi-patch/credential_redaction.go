// CREDENTIAL REDACTION — CyberTestify yamasi (bkz repo kokundeki PATCHES.md).
//
// Amac (Tam Kapsamlı Pentest — FAZ B, defense-in-depth): flow/tool LOG'una bir metin YAZILMADAN
// once, BILINEN kimlik bilgisi degerlerini ([CREDENTIAL_REDACTED]) maskelemek. Bu BIRINCIL koruma
// DEGILDIR — mimari geregi sifre ajana/PentAGI'ye HIC gonderilmez (backend deterministik login
// yapip yalniz OTURUM token'ini gecirir; bkz backend authLogin.ts). Bu katman, gelecekte bir hata/
// yeni kontrol yanlislikla bir kimlik bilgisi benzeri degeri loglarsa diye SON guvenlik agidir.
//
// PII redaksiyonu (pii_redaction.go) YAPISAL veriyi desenle maskeler; kimlik bilgisi ise DEGER-
// tabanlidir (rastgele string) — bu yuzden ayri, deger-listesi alan bir fonksiyon gerekir.
package provider

import (
	"regexp"
	"sort"
	"strings"
)

const credentialToken = "[CREDENTIAL_REDACTED]"
const minSecretLen = 3 // cok kisa degerleri maskeleme (asiri-redaksiyon/yanlis-pozitif riski)

// RedactSecrets, metindeki verilen kimlik bilgisi degerlerini maskeler. Uzun degerler ONCE
// maskelenir (kisa bir parca uzun bir degerin icindeyken bozulma olmasin). Regex-ozel karakterler
// escape edilir; ham deger + JSON-kacisli govde ("s3\"cret") birlikte aranir.
func RedactSecrets(s string, secrets []string) string {
	if s == "" || len(secrets) == 0 {
		return s
	}
	needles := make([]string, 0, len(secrets)*2)
	seen := map[string]bool{}
	addNeedle := func(v string) {
		if len(v) < minSecretLen || seen[v] {
			return
		}
		seen[v] = true
		needles = append(needles, v)
	}
	for _, v := range secrets {
		v = strings.TrimSpace(v)
		addNeedle(v)
		// JSON-kacisli gomulu form (dis tirnaklar haric): \" \\ vb.
		esc := strings.ReplaceAll(v, `\`, `\\`)
		esc = strings.ReplaceAll(esc, `"`, `\"`)
		if esc != v {
			addNeedle(esc)
		}
	}
	sort.Slice(needles, func(i, j int) bool { return len(needles[i]) > len(needles[j]) })
	for _, n := range needles {
		s = regexp.MustCompile(regexp.QuoteMeta(n)).ReplaceAllString(s, credentialToken)
	}
	return s
}

// ContainsSecret, metin verilen degerlerden birini ACIKTA iceriyor mu? (guard/test icin)
func ContainsSecret(s string, secrets []string) bool {
	for _, v := range secrets {
		v = strings.TrimSpace(v)
		if len(v) < minSecretLen {
			continue
		}
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}
