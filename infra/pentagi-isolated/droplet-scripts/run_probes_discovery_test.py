#!/usr/bin/env python3
"""
(REGRESYON — MALİYETSİZ) run_probes.py hedefe-özel KEŞİF testi: GERÇEK tarama ÇALIŞTIRMADAN, örnek ana-sayfa
HTML'inden extract_entrypoints'in hedefin GERÇEK parametreli uçlarını (asp/aspx/php/form) çıkardığını; harici
host / protokol-göreli / statik varlıkların ELENDİĞİNİ doğrular. Kök neden: hardcoded testfire path'leri her
hedefte deneniyordu → testasp/ASP'de 404 → yanlış "Temiz". Çalıştır: python3 run_probes_discovery_test.py
"""
import importlib.util, sys
spec = importlib.util.spec_from_file_location("rp", "run_probes.py")
rp = importlib.util.module_from_spec(spec); spec.loader.exec_module(rp)
HTML = ('<a href="/Search.asp?tfSearch=test">S</a><a href="/products.aspx?catid=3&sort=asc">P</a>'
        '<a href="https://evil.example.com/x?q=1">e</a><a href="https://testasp.vulnweb.com/self.asp?id=9">s</a>'
        '<a href="//cdn.other.com/a?z=1">c</a><a href="/logo.png?v=2">l</a>'
        '<form action="/comment.php" method="get"><input type="text" name="author">'
        '<input type="hidden" name="csrf"><input type="submit"></form>')
eps = rp.extract_entrypoints(HTML, 'testasp.vulnweb.com')
p = f = 0
def ok(c, m):
    global p, f; p += bool(c); f += (not c); print(('PASS' if c else 'FAIL') + ' · ' + m)
ok(('/Search.asp', 'tfSearch') in eps, 'göreli ASP link → alındı (hedefe-özel, hardcoded değil)')
ok(('/products.aspx', 'catid') in eps, 'çok-paramlı link → ilk param')
ok(('/self.asp', 'id') in eps, 'aynı-host mutlak URL → alındı')
ok(('/comment.php', 'author') in eps, 'PHP form action + ilk anlamlı input → alındı')
ok(not any(pp == '/x' for pp, _ in eps), 'HARİCİ host (evil→/x) ELENDİ (provenance)')
ok(not any(pp == '/a' for pp, _ in eps), 'protokol-göreli (//cdn→/a) ELENDİ')
ok(not any(pp == '/logo.png' for pp, _ in eps), 'statik png ELENDİ')
ok(not any(par == 'csrf' for _, par in eps), 'gizli input atlandı')
print(f"\n=== {p} geçti, {f} başarısız ===")
sys.exit(1 if f else 0)
