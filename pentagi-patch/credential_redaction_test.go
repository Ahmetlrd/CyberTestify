// credential_redaction_test.go — CyberTestify. Calistir: go test ./... (pentagi build agacinda).
package provider

import "testing"

func TestRedactSecrets_BasicMasking(t *testing.T) {
	user := "pentest_tester_01"
	pass := "S3cr3t!Passw0rd#42"
	line := "LOGIN username=" + user + " password=" + pass
	red := RedactSecrets(line, []string{user, pass})
	if contains(red, user) || contains(red, pass) {
		t.Fatalf("kimlik bilgisi maskelenmedi: %q", red)
	}
	if !contains(red, credentialToken) {
		t.Fatalf("redaction token yok: %q", red)
	}
}

func TestRedactSecrets_RegexSpecialChars(t *testing.T) {
	weird := "a.b*c(d)e|f$g"
	red := RedactSecrets("x="+weird, []string{weird})
	if contains(red, weird) {
		t.Fatalf("regex-ozel karakterli sifre maskelenmedi: %q", red)
	}
}

func TestRedactSecrets_JSONEscapedBody(t *testing.T) {
	pass := `pa"ss\word`
	body := `{"password":"pa\"ss\\word"}`
	red := RedactSecrets(body, []string{pass})
	if contains(red, `pa\"ss\\word`) {
		t.Fatalf("JSON-kacisli govde maskelenmedi: %q", red)
	}
}

func TestContainsSecret(t *testing.T) {
	user, pass := "tester", "longenoughsecret"
	if !ContainsSecret("u=tester p=longenoughsecret", []string{user, pass}) {
		t.Fatal("ham metinde sizinti tespit edilemedi")
	}
	red := RedactSecrets("u=tester p=longenoughsecret", []string{user, pass})
	if ContainsSecret(red, []string{user, pass}) {
		t.Fatalf("redakte metinde hala sizinti gorunuyor: %q", red)
	}
}

func TestRedactSecrets_ShortIgnored(t *testing.T) {
	// <3 karakter degerler maskelenmemeli (asiri-redaksiyon riski)
	if RedactSecrets("the a x", []string{"a", ""}) != "the a x" {
		t.Fatal("kisa/bos deger yanlislikla maskelendi")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
