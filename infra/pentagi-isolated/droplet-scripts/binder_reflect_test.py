#!/usr/bin/env python3
"""
(REGRESYON — MALİYETSİZ) S1 kanıt-yakalama zincirinin fixture testi: GERÇEK droplet/tarama ÇALIŞTIRMADAN,
sahte örnek yanıtlarla binder.reflected_xss davranışını doğrular. Amaç: run_probes.py'nin bounded-curl
düzeltmesi sayesinde YAKALANAN reflected-marker yanıtının binder'da KANITLI XSS olarak bağlandığını; ama
yakalanamayan (PROBE_TIMEOUT) / kodlanmış (&lt;) / reddedilen (4xx) durumların KANITLI ÜRETMEDİĞİNİ
(anti-hayalet kural korunuyor) kanıtlamak. Çalıştır: python3 binder_reflect_test.py
"""
import sys, importlib.util
spec = importlib.util.spec_from_file_location("binder", "binder.py")
binder = importlib.util.module_from_spec(spec); spec.loader.exec_module(binder)

CMD = ('curl -sk -i --connect-timeout 15 --max-time 40 -G --resolve testasp.vulnweb.com:443:1.2.3.4 '
       '"https://testasp.vulnweb.com/bank/searchpage.jsp" --data-urlencode "searchStr=zqxmarker9173<script>alert(1)</script>"')
def art(raw): return {'id': 'probe#3', 'kind': 'terminal', 'command': CMD, 'rawText': raw}

p = f = 0
def ok(c, m):
    global p, f
    p += bool(c); f += (not c)
    print(('PASS' if c else 'FAIL') + ' · ' + m)

# 1) YAKALANMIŞ reflected yanıt (fix'in artık güvenilir ürettiği kanıt) → KANITLI XSS
captured = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Results for: zqxmarker9173<script>alert(1)</script> (0 found)</body></html>"
r = binder.reflected_xss('xss', [art(captured)])
ok(bool(r) and r.get('signature') == 'reflected-unencoded',
   'yakalanan reflected-marker yanıtı → KANITLI reflected-XSS')

# 2) PROBE_TIMEOUT (eski bug'ın boş kanıtı) → KANITLI DEĞİL (yakalanmayan kanıt uydurulmaz)
ok(binder.reflected_xss('xss', [art('PROBE_TIMEOUT (60s)')]) is None,
   'PROBE_TIMEOUT → KANITLI değil (uydurma yok)')

# 3) ENCODE EDİLMİŞ yansıma → KANITLI DEĞİL (dürüst; kodlanmışsa güvenli)
enc = "HTTP/1.1 200 OK\r\n\r\n<html>Results for: zqxmarker9173&lt;script&gt;alert(1)&lt;/script&gt;</html>"
ok(binder.reflected_xss('xss', [art(enc)]) is None, 'kodlanmış yansıma → KANITLI değil')

# 4) 4xx (istek reddedildi) → KANITLI DEĞİL
ok(binder.reflected_xss('xss', [art("HTTP/1.1 403 Forbidden\r\n\r\n<script>zqxmarker9173<script>alert(1)</script>")]) is None,
   '4xx yanıt → KANITLI değil')

print(f"\n=== {p} geçti, {f} başarısız ===")
sys.exit(1 if f else 0)
