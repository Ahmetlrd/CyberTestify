import { ImageResponse } from 'next/og';

// (SEO) Site-geneli Open Graph / Twitter kart görseli — 1200×630 markalı PNG, build/edge'de üretilir
// (statik binary asset gerektirmez). Next bunu tüm rotalara openGraph.images olarak OTOMATİK ekler.
export const runtime = 'edge';
export const alt = 'CyberTestify — Yapay zekâ destekli otomatik güvenlik taraması';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          padding: '80px',
          background: 'linear-gradient(135deg, #0C2B27 0%, #123F3A 55%, #1C6B60 100%)',
          color: '#ffffff',
          fontFamily: 'sans-serif',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
          <div
            style={{
              width: 56,
              height: 56,
              borderRadius: 14,
              background: '#F5A623',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 34,
              fontWeight: 800,
              color: '#123F3A',
            }}
          >
            ✓
          </div>
          <div style={{ fontSize: 40, fontWeight: 800, letterSpacing: -0.5 }}>
            Cyber<span style={{ color: '#F5A623' }}>Testify</span>
          </div>
        </div>
        <div style={{ marginTop: 48, fontSize: 62, fontWeight: 800, lineHeight: 1.1, maxWidth: 900 }}>
          Yapay zekâ destekli otomatik güvenlik taraması
        </div>
        <div style={{ marginTop: 28, fontSize: 30, color: 'rgba(255,255,255,0.82)', maxWidth: 940 }}>
          Dakikalar içinde başlar · Yalnızca doğrulanmış alan adları · Şifreli rapor
        </div>
      </div>
    ),
    { ...size },
  );
}
