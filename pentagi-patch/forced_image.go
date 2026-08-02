package tools

// FORCED PRIMARY IMAGE — CyberTestify yamasi.
//
// NEDEN: PentAGI'de bir flow'un terminal (primary) container image'ini LLM SECIYOR
// (bkz providers.go image_chooser.tmpl). Ajan cogu zaman ciplak bir public image
// (debian:latest / ubuntu:latest) seciyor; bu image'larda curl/openssl/dig/wget/
// python3 YOK. Sonucta ssl_tls / dns_email gibi CLI-araci gerektiren pasif paketlerde
// ajan butun tool-call butcesini araci kurmaya/aramaya harciyor ve rapor bos cikiyor.
//
// COZUM: primary container image'ini — LLM ne secerse secsin — pasif-recon araclari
// GOMULU tek bir image'a SABITLERIZ (tool-level garanti, prompt degil). Bu, GET-only
// guard ile ayni felsefe: insan/LLM hafizasina degil, kod seviyesine guveniriz.
//
// Deger ENV ile gecersiz kilinabilir (PENTAGI_FORCED_IMAGE); bos/tanimsizsa varsayilan
// cybertestify/pentagi-terminal:tools (bkz pentagi-patch/terminal-tools.Dockerfile).
//
// Cagri yeri: pkg/tools/tools.go flowToolsExecutor.Prepare() — ContainerTypePrimary
// olusturulan TEK nokta (Image: ForcedPrimaryImage()).

import "os"

const defaultForcedPrimaryImage = "cybertestify/pentagi-terminal:tools"

// ForcedPrimaryImage, primary (terminal) container icin kullanilacak SABIT image'i doner.
func ForcedPrimaryImage() string {
	if v := os.Getenv("PENTAGI_FORCED_IMAGE"); v != "" {
		return v
	}
	return defaultForcedPrimaryImage
}
