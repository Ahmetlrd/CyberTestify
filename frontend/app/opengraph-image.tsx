import { ImageResponse } from 'next/og';

// (SEO) Site-geneli Open Graph / Twitter kart görseli — 1200×630 markalı PNG, sunucuda üretilir.
// NOT: Satori (ImageResponse) yerleşik fontu yalnız Latin-ASCII kapsar; Türkçe diakritik/emoji offline
// build'de font indirme (HTTP 400) tetikler. Bu yüzden görsel metni ASCII/İngilizce tutulur. Ayrıca
// birden fazla çocuğu olan HER <div> explicit `display:flex` almalıdır (Satori kuralı).
export const runtime = 'nodejs';
export const alt = 'CyberTestify — AI-assisted automated website security scanning';
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
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <div
            style={{
              display: 'flex',
              width: 56,
              height: 56,
              borderRadius: 14,
              marginRight: 20,
              background: '#F5A623',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 28,
              fontWeight: 800,
              color: '#123F3A',
            }}
          >
            CT
          </div>
          <div style={{ display: 'flex', fontSize: 40, fontWeight: 800 }}>
            <span>Cyber</span>
            <span style={{ color: '#F5A623' }}>Testify</span>
          </div>
        </div>
        <div style={{ display: 'flex', marginTop: 48, fontSize: 60, fontWeight: 800, lineHeight: 1.1, maxWidth: 940 }}>
          AI-assisted automated website security scanning
        </div>
        <div style={{ display: 'flex', marginTop: 28, fontSize: 30, color: 'rgba(255,255,255,0.82)', maxWidth: 960 }}>
          Starts in minutes - Verified domains only - Encrypted report
        </div>
      </div>
    ),
    { ...size },
  );
}
