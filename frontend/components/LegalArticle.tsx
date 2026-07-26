import Link from 'next/link';
import { COMPANY } from '../lib/company';

/**
 * Hukuki sayfalar icin ortak sarmalayici. Ustte "taslak — avukat onayi gerekir"
 * uyarisi ve son guncelleme tarihi gosterir.
 */
export function LegalArticle({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <main style={{ lineHeight: 1.7 }}>
      <p style={{ fontSize: 13 }}>
        <Link href="/">← Ana sayfa</Link>
      </p>
      <div
        style={{
          background: '#fff8e1',
          border: '1px solid #f0d000',
          borderRadius: 8,
          padding: 12,
          fontSize: 13,
          marginBottom: 16,
        }}
      >
        <strong>Taslak metin.</strong> Bu sayfa bilgilendirme amaçlı bir şablondur ve yayına
        alınmadan önce bir avukat/mali müşavir tarafından incelenip <em>[köşeli parantez]</em>
        içindeki işletme bilgileriyle tamamlanmalıdır. Hukuki mütalaa değildir.
      </div>
      <h1>{title}</h1>
      <p style={{ fontSize: 13, color: '#57606a' }}>
        Son güncelleme: {COMPANY.lastUpdated} · Sürüm: {COMPANY.legalVersion}
      </p>
      {children}
    </main>
  );
}
