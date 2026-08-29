import Link from 'next/link';
import { cookies } from 'next/headers';
import { getRegion } from '../../config/regions';

// (Çok-bölge) Bölge-bağımsız kök sayfa; dili region cookie'sinden alır (hakkimizda/iletisim ile aynı desen).
// MIT lisans metni HUKUKİ bildirim olduğundan çevrilmez — İngilizce orijinal aynen kalır.
const T = {
  tr: {
    metaTitle: 'Açık Kaynak Bileşenler — CyberTestify',
    metaDesc: 'CyberTestify altyapısında yararlanılan açık kaynak projeler ve lisans bildirimleri.',
    title: 'Açık Kaynak Bileşenler',
    intro: 'CyberTestify, bazı açık kaynak projelerden yararlanır. İlgili lisans bildirimleri aşağıdadır.',
    bodyHtml: 'CyberTestify altyapısının bir kısmı, MIT Lisansı altında dağıtılan <a href="https://github.com/vxcontrol/pentagi" target="_blank" rel="noopener noreferrer" class="text-accent-600 underline">PentAGI</a> (Copyright © 2025 PentAGI Development Team) projesinden yararlanmaktadır.',
    back: '← Hakkımızda',
  },
  de: {
    metaTitle: 'Open-Source-Komponenten — CyberTestify',
    metaDesc: 'In der CyberTestify-Infrastruktur verwendete Open-Source-Projekte und Lizenzhinweise.',
    title: 'Open-Source-Komponenten',
    intro: 'CyberTestify nutzt einige Open-Source-Projekte. Die entsprechenden Lizenzhinweise finden Sie unten.',
    bodyHtml: 'Ein Teil der CyberTestify-Infrastruktur nutzt das unter der MIT-Lizenz veröffentlichte Projekt <a href="https://github.com/vxcontrol/pentagi" target="_blank" rel="noopener noreferrer" class="text-accent-600 underline">PentAGI</a> (Copyright © 2025 PentAGI Development Team).',
    back: '← Über uns',
  },
  en: {
    metaTitle: 'Open-Source Components — CyberTestify',
    metaDesc: 'Open-source projects used in the CyberTestify infrastructure and their license notices.',
    title: 'Open-Source Components',
    intro: 'CyberTestify makes use of some open-source projects. The relevant license notices are below.',
    bodyHtml: 'Part of the CyberTestify infrastructure uses <a href="https://github.com/vxcontrol/pentagi" target="_blank" rel="noopener noreferrer" class="text-accent-600 underline">PentAGI</a> (Copyright © 2025 PentAGI Development Team), distributed under the MIT License.',
    back: '← About us',
  },
} as const;

const MIT_LICENSE = `MIT License

Copyright (c) 2025 PentAGI Development Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`;

function pick() {
  const region = getRegion(cookies().get('region')?.value);
  const lang = region.lang === 'de' ? 'de' : region.lang === 'en' ? 'en' : 'tr';
  return { t: T[lang] };
}

export function generateMetadata() {
  const { t } = pick();
  return {
    title: t.metaTitle,
    description: t.metaDesc,
    alternates: { canonical: '/acik-kaynak' },
  };
}

export default function OpenSourcePage() {
  const { t } = pick();
  return (
    <main className="container-page max-w-2xl py-14">
      <h1 className="text-3xl font-extrabold text-brand">{t.title}</h1>
      <p className="mt-3 text-sm leading-relaxed text-ink-soft">{t.intro}</p>

      <section className="mt-8 space-y-6">
        <div className="card p-6">
          <h2 className="text-lg font-bold text-brand">PentAGI</h2>
          <p className="mt-2 text-sm leading-relaxed text-ink-soft" dangerouslySetInnerHTML={{ __html: t.bodyHtml }} />
          <pre className="mt-4 overflow-x-auto rounded-card bg-brand-50/60 p-4 text-xs leading-relaxed text-ink-soft">
{MIT_LICENSE}
          </pre>
        </div>
      </section>

      <p className="mt-8 text-sm text-ink-soft">
        <Link href="/hakkimizda" className="text-accent-600 underline">{t.back}</Link>
      </p>
    </main>
  );
}
