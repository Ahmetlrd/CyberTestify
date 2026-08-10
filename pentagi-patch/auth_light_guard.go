// AUTHENTICATED-LIGHT HTTP GUARD — CyberTestify yamasi (Tam Kapsamlı Pentest FAZ D).
//
// active-light profilinin TÜMÜNÜ miras alır (bkz IsBlockedHTTPCommand) + EK olarak: HESAP-DURUMU
// DEĞİŞTİREN yazma isteklerini (parola/e-posta değiştirme, hesap silme, sipariş/ödeme TAMAMLAMA,
// abonelik, iade) — POST bile olsa — BLOKLAR. Yalnız bu paketin ajan-katmanı adımlarında kullanılır;
// FAZ C'nin deterministik kontrolleri kendi güvenli backend fonksiyonlarıyla çalışır (buna tabi değil).
//
// LOGIN İSTİSNASI: login/signin/authenticate/session yolları account-change blocklist'inde DEĞİLDİR;
// dolayısıyla login POST'u (FAZ B backend'in kullandığı uç) bu profilde de SERBESTTİR — ajan zaten
// login denemez, ama guard seviyesinde çakışma olmaz.
package tools

import "regexp"

// Bir komutta veri-YAZAN HTTP eylemi göstergesi (POST dahil — active-light POST'a izin verir, ama
// account-change YOLUYLA birleşince authenticated-light bunu bloklar).
var authLightWriteIndicator = regexp.MustCompile(`(?i)(-X\s*['"]?(POST|PUT|PATCH|DELETE)|--request\s+['"]?(POST|PUT|PATCH|DELETE)|(^|\s)(-d|--data|--data-raw|--data-binary|--data-urlencode|-F|--form)(\s|=)|requests\.(post|put|patch|delete)\s*\(|\.method\s*=\s*['"](POST|PUT|PATCH|DELETE)['"]|\b(POST|PUT|PATCH|DELETE)\s+/\S*\s+HTTP/)`)

// Hesap-durumu değiştiren / tamamlama yolları (login HARİÇ — bilerek listede yok).
var authLightBlockedPaths = regexp.MustCompile(`(?i)(change[-_/]?password|reset[-_/]?password|update[-_/]?password|password[-_/]?(change|update|reset)|delete[-_/]?account|account[-_/]?delet|remove[-_/]?account|close[-_/]?account|deregister|change[-_/]?email|update[-_/]?email|email[-_/]?(change|update)|/pay(ment)?\b|/checkout\b|/charge\b|/billing\b|order[-_/]?(complete|confirm|place)|/purchase\b|/subscribe\b|/unsubscribe\b|/refund\b)`)

// AuthLightExtraBlocked: authenticated-light profiline ÖZGÜ ek blok — yazma göstergesi VE
// account-change/checkout yolu birlikteyse (true, eşleşme). Aksi halde (salt-okuma, login, sepet vb.)
// active-light kuralları geçerli.
func AuthLightExtraBlocked(command string) (bool, string) {
	if !authLightWriteIndicator.MatchString(command) {
		return false, ""
	}
	if m := authLightBlockedPaths.FindString(command); m != "" {
		return true, m
	}
	return false, ""
}
