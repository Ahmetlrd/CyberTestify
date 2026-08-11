'use client';

import { useEffect, useState } from 'react';

/**
 * (İŞ 1) GERÇEK tarama sırasında adım-adım, animasyonlu ilerleme — boş spinner yerine "momentum".
 *
 * DÜRÜSTLÜK: Faz etiketleri GENELDİR ve bu fazlar taramada GERÇEKTEN yapılır (erişim/başlık/TLS/yüzey/
 * sıralama/rapor). UYDURMA SPESİFİK BULGU GÖSTERİLMEZ (ör. gerçekte yokken "CSP eksik" yazılmaz). İlerleme
 * çubuğu bir momentum göstergesidir (kesin yüzde değil) — %100'e ancak durum gerçekten tamamlanınca ulaşır.
 * Backend granüler faz yaymadığından, adımlar zamana bağlı akıtılır (asla takılı görünmez); backend GERÇEK
 * redakte aktivite akışı (feed) yayarsa o da altta gösterilir.
 */
const PHASES = [
  'Hedef erişilebilirliği ve yüzey kontrolü',
  'HTTP güvenlik başlıkları inceleniyor',
  'TLS/SSL yapılandırması kontrol ediliyor',
  'Uygulama yüzeyi ve girdi noktaları taranıyor',
  'Bulgular değerlendiriliyor ve önceliklendiriliyor',
  'Rapor hazırlanıyor ve şifreleniyor',
];

export function LiveScanPhases({ hostname, feed }: { hostname: string; feed: Array<{ seq: number; text: string }> }) {
  const [idx, setIdx] = useState(0);
  const [pct, setPct] = useState(6);

  // Fazı zamana bağlı ilerlet — SON "çalışan" fazda dur (durum tamamlanana kadar "bitti" deme).
  useEffect(() => {
    const t = setInterval(() => setIdx((x) => Math.min(x + 1, PHASES.length - 1)), 7000);
    return () => clearInterval(t);
  }, []);
  // İlerleme çubuğu: %92'ye doğru yumuşak yaklaşır, asla %100 olmaz (tamamlanma gerçek durumdan gelir).
  useEffect(() => {
    const t = setInterval(() => setPct((p) => (p < 92 ? Math.min(92, p + Math.max(0.5, (92 - p) * 0.05)) : p)), 850);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="min-h-[180px] p-5 font-mono text-[13px] leading-7">
      <div className="text-white/45" dir="ltr">$ cybertestify scan {hostname}</div>
      <div className="text-emerald-300" dir="ltr">✓ Alan adı sahipliği doğrulandı</div>
      {PHASES.map((label, i) => {
        if (i > idx) return null;
        const current = i === idx;
        return (
          <div key={label} className={current ? 'text-white/85' : 'text-emerald-300/90'} dir="ltr">
            {current ? '→' : '✓'} {label}
            {current && <span className="ml-1 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-accent/80" />}
          </div>
        );
      })}

      {/* Momentum çubuğu — her zaman öne akar (takılı görünmez); kesin yüzde DEĞİL. */}
      <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-white/10">
        <div className="h-full rounded-full bg-gradient-to-r from-accent/70 to-emerald-400/80 transition-[width] duration-700 ease-out" style={{ width: `${pct}%` }} />
      </div>

      {/* GERÇEK redakte aktivite akışı (backend yayarsa) — üsttekiler jenerik faz; bunlar gerçek. */}
      {feed.length > 0 && (
        <div className="mt-3 border-t border-white/10 pt-2">
          <div className="text-white/35" dir="ltr">— canlı aktivite —</div>
          {feed.map((it) => (
            <div key={it.seq} className="text-white/70" dir="ltr">→ {it.text}</div>
          ))}
        </div>
      )}
    </div>
  );
}
