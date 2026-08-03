// PASSIVE / ACTIVE-LIGHT HTTP GUARD — CyberTestify yamasi (bkz repo kokundeki PATCHES.md).
//
// Amac: CyberTestify paketleri GUVENLIK PROFILINE gore farkli HTTP-metot politikasi uygular.
// Ajan terminalde yasak bir HTTP eylemi calistirmaya kalkarsa ARAC SEVIYESINDE reddedilir —
// komut HIC calismaz. Bu bir PROMPT talimati DEGIL, TEKNIK garantidir.
//
// Profiller (bkz backend ScanPackageDef.securityProfile):
//   - passive (VARSAYILAN): yalniz GET/HEAD/OPTIONS. POST/PUT/DELETE/PATCH + veri gonderen
//     tum bayraklar bloklu. Mevcut TUM paketler bu profildedir.
//   - active-light: zafiyeti DOGRULAMAK icin kontrollu POST/form SERBEST; ama PUT/DELETE/
//     PATCH (veri silme/degistirme), dosya yukleme (-T/--upload-file), toplu veri cekme
//     (sqlmap --dump, INTO OUTFILE) ve DoS/flood araclari (ab/wrk/siege/hping/slowhttptest,
//     "while true" curl dongusu) KESINLIKLE bloklu. HENUZ HICBIR PAKETE ATANMADI.
//
// Kapsam: terminal.go -> ExecCommand girisinde cagrilir; curl/wget/python vb. TUM shell HTTP
// araclari (transport-bagimsiz, HTTPS dahil) tek chokepoint'te suzulur.
//
// Profil kaynagi: SecurityProfileFromEnv() -> PENTAGI_SECURITY_PROFILE (varsayilan "passive").
// Per-flow otoriter kaynak backend /internal/active-scope'tur (concurrency=1); active-light
// bir paket devreye girdiginde bu env oradan beslenir. Su an tum paketler passive.
//
// Kapatma: PENTAGI_GET_ONLY=false passive metot blogunu tamamen devre disi birakir (acik gelir).
//
// Sinir (durustluk): komut-string analizi; agir obfuscation (base64 | sh) atlatabilir. Bu yuzden
// worker seviyesindeki reaktif strict-halt IKINCI KATMAN olarak KORUNUR (defense-in-depth).
package tools

import (
	"os"
	"regexp"
)

// passive: veri-DEGISTIREN TUM HTTP metotlari (POST dahil) bloklu.
var writeHTTPPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)-X\s*['"]?(POST|PUT|DELETE|PATCH)\b`),
	regexp.MustCompile(`(?i)--request\s+['"]?(POST|PUT|DELETE|PATCH)\b`),
	regexp.MustCompile(`(?i)\bcurl\b[^|;&]*?(^|\s)(-d|--data|--data-raw|--data-binary|--data-urlencode|-F|--form|-T|--upload-file)(\s|=)`),
	regexp.MustCompile(`(?i)\bwget\b[^|;&]*?(--method\s*=\s*['"]?(POST|PUT|DELETE|PATCH)|--post-data|--post-file|--body-data|--body-file)`),
	regexp.MustCompile(`(?i)requests\.(post|put|delete|patch)\s*\(`),
	regexp.MustCompile(`(?i)\.method\s*=\s*['"](POST|PUT|DELETE|PATCH)['"]`),
	regexp.MustCompile(`(?i)\b(POST|PUT|DELETE|PATCH)\s+/\S*\s+HTTP/`),
}

// active-light: POST SERBEST; ama PUT/DELETE/PATCH + upload + exfil + DoS bloklu.
var activeLightBlockedPatterns = []*regexp.Regexp{
	// yikici metotlar (POST HARIC)
	regexp.MustCompile(`(?i)-X\s*['"]?(PUT|DELETE|PATCH)\b`),
	regexp.MustCompile(`(?i)--request\s+['"]?(PUT|DELETE|PATCH)\b`),
	regexp.MustCompile(`(?i)requests\.(put|delete|patch)\s*\(`),
	regexp.MustCompile(`(?i)\.method\s*=\s*['"](PUT|DELETE|PATCH)['"]`),
	regexp.MustCompile(`(?i)\b(PUT|DELETE|PATCH)\s+/\S*\s+HTTP/`),
	// dosya yukleme (veri yazar)
	regexp.MustCompile(`(?i)\bcurl\b[^|;&]*?(^|\s)(-T|--upload-file)(\s|=)`),
	regexp.MustCompile(`(?i)\bwget\b[^|;&]*?--method\s*=\s*['"]?(PUT|DELETE|PATCH)`),
	// toplu veri cekme / exfil
	regexp.MustCompile(`(?i)\bsqlmap\b[^|;&]*?(--dump\b|--dump-all|--os-shell|--os-pwn|--file-read|--file-write|-a\b|--all\b)`),
	regexp.MustCompile(`(?i)\binto\s+(outfile|dumpfile)\b`),
	// DoS / flood araclari ve dongulu sel
	regexp.MustCompile(`(?i)\b(ab|wrk|siege|hping3?|slowloris|slowhttptest|mhddos|goldeneye)\b`),
	regexp.MustCompile(`(?i)\b(while\s+true|for\b[^;]*\bseq\s+\d{3,})\b.*\b(curl|wget|nc|ncat)\b`),
	regexp.MustCompile(`(?i)\bab\b[^|;&]*?-n\s*\d{4,}`),
}

// GetOnlyEnforced: passive GET-only politikasi acik mi (varsayilan: acik).
func GetOnlyEnforced() bool {
	return os.Getenv("PENTAGI_GET_ONLY") != "false"
}

// SecurityProfileFromEnv: aktif guvenlik profili (varsayilan "passive").
func SecurityProfileFromEnv() string {
	if p := os.Getenv("PENTAGI_SECURITY_PROFILE"); p == "active-light" {
		return "active-light"
	}
	return "passive"
}

// IsBlockedHTTPCommand: komut, verilen guvenlik profili altinda YASAK bir HTTP eylemi
// iceriyorsa (true, eslesme) doner. "post" kelimesinin URL icinde gecmesi (or. /api/posts)
// tetiklemez — yalnizca metot bayraklari/fonksiyonlari eslesir.
func IsBlockedHTTPCommand(command string, profile string) (bool, string) {
	if profile == "active-light" {
		// POST serbest; yalniz yikici/exfil/DoS bloklu.
		for _, re := range activeLightBlockedPatterns {
			if m := re.FindString(command); m != "" {
				return true, m
			}
		}
		return false, ""
	}
	// passive (varsayilan): GET-only. Kapatilmadiysa TUM write metotlari bloklu.
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

// IsWriteHTTPCommand: geriye-uyum sarmalayicisi (passive profil). terminal.go hook'u artik
// IsBlockedHTTPCommand(command, SecurityProfileFromEnv()) cagirir; bu yalniz passive-esdegeri.
func IsWriteHTTPCommand(command string) (bool, string) {
	return IsBlockedHTTPCommand(command, "passive")
}
