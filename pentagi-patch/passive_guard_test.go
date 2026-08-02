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
