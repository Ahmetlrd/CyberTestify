// auth_light_guard_test.go — CyberTestify FAZ D. go test ./...
package tools

import "testing"

func TestAuthLightExtraBlocked_BlocksAccountChangePosts(t *testing.T) {
	blocked := []string{
		`curl -X POST https://t.example/rest/user/change-password -d 'new=x'`,
		`curl -d 'email=a@b.c' https://t.example/api/account/update-email`,
		`curl -X POST https://t.example/api/checkout`,
		`curl --data 'x=1' https://t.example/rest/basket/checkout`,
		`curl -X POST https://t.example/api/account/delete`,
		`requests.post("https://t.example/order/complete", json={})`,
		`curl -X POST https://t.example/api/payment -d 'amount=1'`,
	}
	for _, c := range blocked {
		if ok, _ := AuthLightExtraBlocked(c); !ok {
			t.Fatalf("BLOKLANMALIYDI ama geçti: %q", c)
		}
	}
}

func TestAuthLightExtraBlocked_AllowsSafeAndLogin(t *testing.T) {
	allowed := []string{
		`curl -X POST https://t.example/rest/user/login -d 'email=a&password=b'`, // login POST — serbest
		`curl https://t.example/rest/admin/application-configuration`,             // GET okuma
		`curl -X POST https://t.example/api/register -d 'email=a&role=admin'`,     // kayıt/mass-assignment (account-change DEĞİL)
		`curl -X POST https://t.example/rest/products/search -d 'q=x'`,            // arama POST
		`curl https://t.example/api/checkout`,                                     // GET (yazma göstergesi yok) — serbest
	}
	for _, c := range allowed {
		if ok, m := AuthLightExtraBlocked(c); ok {
			t.Fatalf("SERBEST OLMALIYDI ama bloklandı (%q): %q", m, c)
		}
	}
}
