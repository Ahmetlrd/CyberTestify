package tools

import "testing"

func TestPassiveGuard_WriteHTTPBlocked(t *testing.T) {
	blocked := []string{
		`curl -X POST https://target.com/login`,
		`curl -XPUT https://target.com/x`,
		`curl --request DELETE https://target.com/x`,
		`curl -d 'user=a&pass=b' https://target.com/login`,
		`curl --data-raw '{"a":1}' https://target.com/api`,
		`curl -F file=@x https://target.com/upload`,
		`wget --method=POST --body-data='a=1' https://target.com/x`,
		`wget --post-data='a=1' https://target.com/x`,
		`python3 -c "import requests; requests.post('https://target.com/x', data={})"`,
		`printf 'POST /login HTTP/1.1\r\nHost: t\r\n\r\n' | nc target.com 80`,
	}
	for _, c := range blocked {
		if ok, _ := IsWriteHTTPCommand(c); !ok {
			t.Errorf("BEKLENEN: bloklanmali ama gecti: %q", c)
		}
	}
}

func TestPassiveGuard_ReadOnlyAllowed(t *testing.T) {
	allowed := []string{
		`curl -s https://target.com/`,
		`curl -I https://target.com/`,                       // HEAD
		`curl -X GET https://target.com/`,                   // GET
		`curl https://target.com/api/posts`,                 // 'posts' URL'de, metot degil
		`curl -o out.html https://target.com/blog/latest-post`,
		`nmap -sV target.com`,
		`dig @8.8.8.8 target.com TXT`,
		`whatweb https://target.com`,
		`echo "we will not POST anything" && curl https://target.com/`,
	}
	for _, c := range allowed {
		if ok, m := IsWriteHTTPCommand(c); ok {
			t.Errorf("BEKLENEN: izin verilmeli ama bloklandi: %q (eslesme=%q)", c, m)
		}
	}
}

// active-light: POST/form SERBEST olmali (zafiyet dogrulama), ama yikici/exfil/DoS bloklu.
func TestActiveLight_PostAllowed(t *testing.T) {
	allowed := []string{
		`curl -X POST -d 'user=a&pass=b' https://target.com/login`, // kontrollu test payload'i
		`curl -F file=@probe.txt https://target.com/upload`,        // form POST (upload degil, -T degil)
		`curl -s https://target.com/`,
		`curl -X GET https://target.com/`,
		`python3 -c "import requests; requests.post('https://target.com/x', data={})"`,
	}
	for _, c := range allowed {
		if ok, m := IsBlockedHTTPCommand(c, "active-light"); ok {
			t.Errorf("active-light BEKLENEN: izin verilmeli ama bloklandi: %q (eslesme=%q)", c, m)
		}
	}
}

func TestActiveLight_DestructiveAndDosBlocked(t *testing.T) {
	blocked := []string{
		`curl -X DELETE https://target.com/api/user/1`,
		`curl -X PUT -d '{}' https://target.com/api/user/1`,
		`curl --request PATCH https://target.com/x`,
		`curl -T bigfile.bin https://target.com/upload`, // dosya yukleme
		`python3 -c "import requests; requests.delete('https://target.com/x')"`,
		`sqlmap -u 'https://target.com/?id=1' --dump`,       // toplu veri cekme
		`sqlmap -u 'https://target.com/?id=1' --dump-all`,
		`ab -n 100000 -c 500 https://target.com/`,           // DoS
		`wrk -t8 -c400 -d60s https://target.com/`,
		`hping3 -S --flood -p 443 target.com`,
		`while true; do curl https://target.com/; done`,     // sel dongusu
		`mysql -e "SELECT * FROM users INTO OUTFILE '/tmp/x'"`,
	}
	for _, c := range blocked {
		if ok, _ := IsBlockedHTTPCommand(c, "active-light"); !ok {
			t.Errorf("active-light BEKLENEN: bloklanmali ama gecti: %q", c)
		}
	}
}
