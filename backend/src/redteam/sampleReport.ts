/**
 * (TEST MODU) Gerçek droplet koşusu OLMADAN, uçtan uca ticari akışı (order → rapor → admin onay →
 * müşteri indirme) test etmek için örnek bir S1 RedTeamReport üretir. Promo (₺0) S1 siparişlerinde
 * kullanılır — gerçek ÖDEMELİ S1 siparişleri her zaman GERÇEK koşu yapar. İçerik açıkça örnek/demodur.
 */
import { buildRedTeamReport, type BinderOutput } from './report.js';

export function sampleRedTeamReport(target: string, generatedAt: string): unknown {
  const binder: BinderOutput = {
    artifactCount: 17,
    claimCount: 9,
    summary: { kanitli: 4, belirsiz: 0, hayalet: 2 },
    filteredMeta: 6,
    eliminatedReasons: { 'off-target': 2 },
    tried: { httpRequests: 26, terminalArtifacts: 22, endpointCount: 4, endpoints: ['/search.jsp', '/bank/searchpage.jsp', '/doLogin', '/login.jsp'], families: ['XSS', 'SQL Enjeksiyonu'] },
    overallRisk: 'orta',
    findings: [
      {
        title: 'Reflected XSS — /search.jsp', category: 'xss', endpoint: '/search.jsp', severity: 'orta', tier: 'KANITLI',
        reason: 'reflected XSS — payload GERÇEK yanıt gövdesinde ENCODE EDİLMEDEN yansıdı',
        evidence: { artifactRef: 'termlog#8', signature: 'reflected-unencoded', marker: 'zqxmarker9173', detail: 'payload yanıt gövdesinde encode edilmeden yansıdı → reflected XSS',
          command: `curl -sk -i -G --resolve ${target}:443:203.0.113.10 "https://${target}/search.jsp" --data-urlencode "query=zqxmarker9173<script>alert(1)</script>"`,
          rawExcerpt: `HTTP/1.1 200 OK (gerçek yanıt · gövde kısaltıldı, reflection çevresi)\n…\n<div class="fl">\n<h1>Search Results</h1>\n<p>No results were found for the query:<br /><br />\nzqxmarker9173<script>alert(1)</script>\n</p>\n</div>` },
      },
      {
        title: 'Bilgi İfşası — Server başlığı sürüm/teknoloji açığa çıkarıyor (Apache-Coyote/1.1)', category: 'info_disclosure', endpoint: '', severity: 'düşük', tier: 'KANITLI',
        reason: 'Server başlığı sürüm/teknoloji ifşa ediyor: \'Apache-Coyote/1.1\' (sunucu geneli)',
        evidence: { artifactRef: 'termlog#6', signature: 'response-header', marker: 'Server:', detail: 'Server başlığı sürüm/teknoloji ifşa ediyor: \'Apache-Coyote/1.1\' (sunucu geneli)',
          command: `curl -sk -i --resolve ${target}:443:203.0.113.10 "https://${target}/"`,
          rawExcerpt: 'HTTP/1.1 200 OK\nServer: Apache-Coyote/1.1\nContent-Type: text/html' },
      },
      {
        title: 'Çerez Güvenlik Bayrağı Eksik: SameSite', category: 'cookie_config', endpoint: '/bank/searchpage.jsp', severity: 'düşük', tier: 'KANITLI',
        reason: 'Set-Cookie eksik güvenlik bayrağı: SameSite — HttpOnly, Secure zaten mevcut (oturum çerezi)',
        evidence: { artifactRef: 'termlog#6', signature: 'response-header', marker: 'Set-Cookie', missing: ['SameSite'], detail: 'Set-Cookie eksik güvenlik bayrağı: SameSite — HttpOnly, Secure zaten mevcut (oturum çerezi)',
          command: `curl -sk -i --resolve ${target}:443:203.0.113.10 "https://${target}/bank/searchpage.jsp"`,
          rawExcerpt: 'HTTP/1.1 302 Found\nServer: Apache-Coyote/1.1\nSet-Cookie: *** Path=/; Secure; HttpOnly\nLocation: /login.jsp' },
      },
      {
        title: 'Eksik Güvenlik Başlığı: X-Frame-Options, Content-Security-Policy', category: 'security_header', endpoint: '/search.jsp', severity: 'düşük', tier: 'KANITLI',
        reason: 'Eksik güvenlik başlıkları — Clickjacking koruması yok (X-Frame-Options); İçerik Güvenlik Politikası yok (Content-Security-Policy)',
        evidence: { artifactRef: 'termlog#8', signature: 'response-header', marker: 'HTTP/', detail: 'Eksik güvenlik başlıkları — Clickjacking koruması yok (X-Frame-Options); İçerik Güvenlik Politikası yok (Content-Security-Policy)',
          command: `curl -sk -i --resolve ${target}:443:203.0.113.10 "https://${target}/search.jsp"`,
          rawExcerpt: 'HTTP/1.1 200 OK\nServer: Apache-Coyote/1.1\nContent-Type: text/html;charset=ISO-8859-1\nContent-Length: 6900' },
      },
    ],
  };
  return buildRedTeamReport(binder, {
    target, level: 'S1', environment: 'prod', generatedAt,
    costUsd: 0, llmCalls: 0, agentSec: 60, elapsedSec: 75,
  });
}
