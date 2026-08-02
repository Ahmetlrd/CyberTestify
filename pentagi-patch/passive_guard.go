// PASSIVE / GET-ONLY GUARD — CyberTestify yamasi (bkz repo kokundeki PATCHES.md).
//
// Amac: CyberTestify paketleri PASIF'tir (yalniz GET/HEAD/OPTIONS). Ajan, terminalde
// veri-DEGISTIREN bir HTTP metodu (POST/PUT/DELETE/PATCH) calistirmaya kalkarsa bu
// ARAC SEVIYESINDE reddedilir — komut HIC calismaz. Bu bir PROMPT talimati degil,
// TEKNIK garantidir (kapsam kilidi dersi: prompt garanti degildir).
//
// Kapsam: terminal.go -> ExecCommand girisinde cagrilir; boylece curl/wget/python vb.
// TUM shell HTTP araclari (transport-bagimsiz) tek chokepoint'te suzulur. HTTPS de
// dahil (istek daha gonderilmeden, komut string'inden yakalanir).
//
// Kapatma: PENTAGI_GET_ONLY=false (varsayilan: ACIK). networkLayer/aktif pentest
// paketleri ileride gerekirse bu env ile gevsetilebilir.
//
// Sinir (durustluk): komut-string analizi; agir obfuscation (base64 | sh, exotik
// araclar) teorik olarak atlatabilir. Bu yuzden worker seviyesindeki reaktif
// strict-halt (findForbiddenMethods) IKINCI KATMAN olarak KORUNUR (defense-in-depth).
package tools

import (
	"os"
	"regexp"
)

var writeHTTPPatterns = []*regexp.Regexp{
	// curl / genel: -X POST | --request POST | -XPOST
	regexp.MustCompile(`(?i)-X\s*['"]?(POST|PUT|DELETE|PATCH)\b`),
	regexp.MustCompile(`(?i)--request\s+['"]?(POST|PUT|DELETE|PATCH)\b`),
	// curl'de veri gonderen bayraklar POST'u zorlar
	regexp.MustCompile(`(?i)\bcurl\b[^|;&]*?(^|\s)(-d|--data|--data-raw|--data-binary|--data-urlencode|-F|--form|-T|--upload-file)(\s|=)`),
	// wget yazma bayraklari
	regexp.MustCompile(`(?i)\bwget\b[^|;&]*?(--method\s*=\s*['"]?(POST|PUT|DELETE|PATCH)|--post-data|--post-file|--body-data|--body-file)`),
	// python requests / benzeri
	regexp.MustCompile(`(?i)requests\.(post|put|delete|patch)\s*\(`),
	regexp.MustCompile(`(?i)\.method\s*=\s*['"](POST|PUT|DELETE|PATCH)['"]`),
	// ham HTTP istek satiri: POST /path HTTP/1.1
	regexp.MustCompile(`(?i)\b(POST|PUT|DELETE|PATCH)\s+/\S*\s+HTTP/`),
}

// GetOnlyEnforced: GET-only politikasi acik mi (varsayilan: acik).
func GetOnlyEnforced() bool {
	return os.Getenv("PENTAGI_GET_ONLY") != "false"
}

// IsWriteHTTPCommand: verilen shell komutu veri-degistiren bir HTTP metodu
// iceriyor mu? Iceriyorsa (true, eslesme) doner. "post" kelimesinin URL icinde
// gecmesi (or. /api/posts) tetiklemez — yalnizca metot bayraklari/fonksiyonlari.
func IsWriteHTTPCommand(command string) (bool, string) {
	if !GetOnlyEnforced() {
		return false, ""
	}
	for _, re := range writeHTTPPatterns {
		if m := re.FindString(command); m != "" {
			return true, m
		}
	}
	return false, ""
}
