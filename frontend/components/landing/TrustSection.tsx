import Link from 'next/link';
import type { RegionConfig } from '../../config/regions';

/**
 * (İTİBAR & GÜVEN — kimlik ifşa etmeden) Ana sayfaya kurumsal güven inşası: somut metrik kartları,
 * gerçek örnek rapor CTA'sı ve teknik güven rozetleri. Şahıs adı / kurucu / LinkedIn İÇERMEZ — yalnız
 * marka + süreç şeffaflığı. Metrikler UYDURMA istatistik değil; mimari/olgusal (üç-katman, kanıt-bağlı,
 * dakikalar-içi, geniş kontrol kapsamı) — projenin "uydurma istatistik yok" ilkesiyle uyumlu.
 */

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

function Icon({ name, className }: { name: string; className?: string }) {
  const p: Record<string, string> = {
    layers: 'M12 2 2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5',
    clock: 'M12 7v5l3 2M12 3a9 9 0 100 18 9 9 0 000-18z',
    shieldCheck: 'M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3zM9 12l2 2 4-4',
    checks: 'M9 11l3 3L22 4M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11',
    box: 'M21 8l-9-5-9 5 9 5 9-5zM3 8v8l9 5 9-5V8M12 13v8',
    lock: 'M5 11h14v10H5V11zM8 11V7a4 4 0 018 0v4',
    scale: 'M12 3v18M5 7h14M7 7l-3 6h6l-3-6zm10 0l-3 6h6l-3-6zM5 21h14',
    card: 'M2 7h20v10H2V7zm0 4h20',
    doc: 'M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8l-6-6zM14 2v6h6M9 13h6M9 17h6',
  };
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d={p[name]} />
    </svg>
  );
}

export function TrustSection({ region }: { region: RegionConfig }) {
  const tr = region.lang === 'tr';
  const de = region.lang === 'de'; // /de: tam Almanca (Sie-form); tr/en mevcut haliyle korunur.

  // D2 — somut, SAVUNULABİLİR metrikler (uydurma yüzde YOK; mimari/olgusal ifadeler)
  const metrics = tr
    ? [
        { icon: 'scale', big: 'Kanıt-Bağlı', label: 'Yalnız teyit edilen bulgular raporlanır — sahte-pozitif elenir' },
        { icon: 'layers', big: '3 Katmanlı', label: 'Hibrit AI + deterministik doğrulama (Kanıtlı / Belirsiz / Hayalet)' },
        { icon: 'clock', big: '< 15 dk', label: 'Ortalama kapsamlı tarama ve rapor üretim süresi' },
        { icon: 'checks', big: '100+', label: 'OWASP Top 10, yanlış-yapılandırma ve mantık-hatası kontrolü' },
      ]
    : de
    ? [
        { icon: 'scale', big: 'Nachweisgebunden', label: 'Nur bestätigte Funde werden gemeldet — Fehlalarme werden eliminiert' },
        { icon: 'layers', big: '3-Schichten', label: 'Hybride KI + deterministische Verifizierung (Belegt / Unsicher / Phantom)' },
        { icon: 'clock', big: '< 15 Min', label: 'Durchschnittliche Zeit für Scan und Berichterstellung' },
        { icon: 'checks', big: '100+', label: 'OWASP Top 10, Fehlkonfigurations- und Logikfehler-Prüfungen' },
      ]
    : [
        { icon: 'scale', big: 'Evidence-Bound', label: 'Only confirmed findings are reported — false-positives eliminated' },
        { icon: 'layers', big: '3-Layer', label: 'Hybrid AI + deterministic verification (Proven / Uncertain / Ghost)' },
        { icon: 'clock', big: '< 15 min', label: 'Average end-to-end scan and report generation time' },
        { icon: 'checks', big: '100+', label: 'OWASP Top 10, misconfiguration and logic-flaw checks' },
      ];

  // D4 — teknik güven rozetleri (olgusal; platformun gerçek özellikleri)
  const badges = tr
    ? [
        { icon: 'box', t: 'İzole Sandbox / Efemer Droplet', s: 'Egress varsayılan-red; her koşu tek-kullanımlık izole ortam' },
        { icon: 'lock', t: '256-Bit Şifreleme', s: 'Raporlar uçtan uca şifreli; tek-kullanımlık erişim koduyla açılır' },
        { icon: 'shieldCheck', t: 'KVKK / GDPR Uyumlu', s: 'Yapısal PII maskeleme; veri işleme uyum-odaklı' },
        { icon: 'card', t: 'Güvenli Ödeme', s: 'iyzico · 3D Secure · kart bilgisi bizde saklanmaz' },
      ]
    : de
    ? [
        { icon: 'box', t: 'Isolierte Sandbox / Kurzlebiger Droplet', s: 'Egress standardmäßig blockiert; jeder Lauf in einer isolierten Einweg-Umgebung' },
        { icon: 'lock', t: '256-Bit-Verschlüsselung', s: 'Berichte Ende-zu-Ende verschlüsselt; mit einem Einmalcode geöffnet' },
        { icon: 'shieldCheck', t: 'DSGVO-konform', s: 'Strukturelle PII-Maskierung; compliance-orientierte Verarbeitung' },
        { icon: 'card', t: 'Sichere Zahlung', s: 'iyzico · 3D Secure · Kartendaten werden bei uns nie gespeichert' },
      ]
    : [
        { icon: 'box', t: 'Isolated Sandbox / Ephemeral Droplet', s: 'Default-deny egress; each run in a single-use isolated env' },
        { icon: 'lock', t: '256-Bit Encryption', s: 'Reports end-to-end encrypted; opened with a one-time code' },
        { icon: 'shieldCheck', t: 'KVKK / GDPR Aligned', s: 'Structural PII redaction; compliance-focused processing' },
        { icon: 'card', t: 'Secure Payment', s: 'iyzico · 3D Secure · card data never stored by us' },
      ];

  const sampleHref = `${API}/orders/sample-report/basit_tarama?v=trust1`;

  return (
    <section id="guven" className="scroll-mt-20 border-t border-line bg-white py-20">
      <div className="container-page">
        {/* D2 — Metrik kartları */}
        <div className="mx-auto max-w-2xl text-center">
          <p className="eyebrow">{tr ? 'Neden güvenebilirsiniz' : de ? 'Warum Sie darauf vertrauen können' : 'Why you can trust it'}</p>
          <h2 className="mt-3 text-3xl font-extrabold leading-tight text-brand">
            {tr ? 'Kanıta dayalı, ' : de ? 'Nachweisbasierte, ' : 'Evidence-driven, '}
            <span className="text-accent-600">{tr ? 'şeffaf doğrulama' : de ? 'transparente Verifizierung' : 'transparent verification'}</span>
          </h2>
          <p className="mt-4 text-lg text-ink-soft">
            {tr
              ? 'Her bulgu, ajanın sözüne değil saklanan HAM istek/yanıt kanıtına bağlanır. Teyit edilmeyen hiçbir şey rapora girmez.'
              : de
              ? 'Jeder Fund ist an gespeicherte ROHE Anfrage-/Antwort-Nachweise gebunden — nicht an den Fließtext des Agenten. Nichts Unbestätigtes gelangt in den Bericht.'
              : 'Every finding is bound to stored RAW request/response evidence — not the agent’s prose. Nothing unconfirmed reaches the report.'}
          </p>
        </div>

        <div className="mx-auto mt-10 grid max-w-5xl gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {metrics.map((m) => (
            <div key={m.big} className="animate-fade-up rounded-card border border-line bg-brand-50/40 p-6 text-center transition hover:border-brand-300 hover:shadow-sm">
              <Icon name={m.icon} className="mx-auto h-7 w-7 text-accent-600" />
              <div className="mt-3 text-2xl font-extrabold text-brand">{m.big}</div>
              <p className="mt-2 text-xs leading-relaxed text-ink-soft">{m.label}</p>
            </div>
          ))}
        </div>

        {/* D3 — Gerçek örnek rapor CTA'sı (kayıt/ödeme YOK) */}
        <div className="mx-auto mt-12 max-w-4xl overflow-hidden rounded-card border-2 border-brand/15 bg-gradient-to-br from-brand-50/70 to-white">
          <div className="flex flex-col items-start gap-5 p-7 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-4">
              <span className="hidden shrink-0 rounded-card bg-brand/10 p-3 text-brand sm:block">
                <Icon name="doc" className="h-7 w-7" />
              </span>
              <div>
                <h3 className="text-xl font-bold text-brand">{tr ? 'Gerçek bir örnek raporu inceleyin' : de ? 'Sehen Sie sich einen echten Beispielbericht an' : 'Explore a real sample report'}</h3>
                <p className="mt-1.5 max-w-xl text-sm text-ink-soft">
                  {tr
                    ? 'Platformun ürettiği teknik derinliği, ham kanıt kesitlerini, yönetici özetini ve hazır düzeltme önerilerini kayıt veya ödeme yapmadan somut olarak görün.'
                    : de
                    ? 'Sehen Sie konkret die technische Tiefe, rohe Nachweisauszüge, die Management-Zusammenfassung und die anwendungsbereiten Korrekturen, die die Plattform erzeugt — ohne Registrierung oder Zahlung.'
                    : 'See the technical depth, raw evidence excerpts, executive summary and ready-to-apply fixes the platform produces — no signup or payment required.'}
                </p>
              </div>
            </div>
            <a
              href={sampleHref}
              target="_blank"
              rel="noopener noreferrer"
              className="btn-primary shrink-0 whitespace-nowrap"
            >
              {tr ? 'Örnek Raporu Aç (PDF)' : de ? 'Beispielbericht öffnen (PDF)' : 'Open Sample Report (PDF)'}
            </a>
          </div>
        </div>

        {/* D4 — Teknik güven rozetleri */}
        <div className="mx-auto mt-12 grid max-w-5xl gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {badges.map((b) => (
            <div key={b.t} className="flex items-start gap-3 rounded-card border border-line bg-white p-4">
              <Icon name={b.icon} className="mt-0.5 h-5 w-5 shrink-0 text-brand" />
              <div>
                <div className="text-sm font-bold text-ink">{b.t}</div>
                <p className="mt-1 text-xs leading-relaxed text-ink-muted">{b.s}</p>
              </div>
            </div>
          ))}
        </div>

        <p className="mx-auto mt-8 max-w-3xl text-center text-xs text-ink-muted">
          {tr
            ? 'Sonuçlar deneysel/otomatik ön-değerlendirmedir; resmi denetim veya sertifikasyon yerine geçmez. Metrikler platformun mimari özelliklerini yansıtır.'
            : de
            ? 'Die Ergebnisse sind eine experimentelle/automatisierte Vorabbewertung; sie ersetzen keine formale Prüfung oder Zertifizierung. Die Kennzahlen spiegeln die architektonischen Eigenschaften der Plattform wider.'
            : 'Results are an experimental/automated pre-assessment; not a substitute for a formal audit or certification. Metrics reflect the platform’s architectural properties.'}
        </p>
      </div>
    </section>
  );
}
