import Link from 'next/link';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Açık Kaynak Bileşenler — CyberTestify',
  description: 'CyberTestify altyapısında yararlanılan açık kaynak projeler ve lisans bildirimleri.',
  alternates: { canonical: '/acik-kaynak' },
};

export default function OpenSourcePage() {
  return (
    <main className="container-page max-w-2xl py-14">
      <h1 className="text-3xl font-extrabold text-brand">Açık Kaynak Bileşenler</h1>
      <p className="mt-3 text-sm leading-relaxed text-ink-soft">
        CyberTestify, bazı açık kaynak projelerden yararlanır. İlgili lisans bildirimleri aşağıdadır.
      </p>

      <section className="mt-8 space-y-6">
        <div className="card p-6">
          <h2 className="text-lg font-bold text-brand">PentAGI</h2>
          <p className="mt-2 text-sm leading-relaxed text-ink-soft">
            CyberTestify altyapısının bir kısmı, MIT Lisansı altında dağıtılan{' '}
            <a href="https://github.com/vxcontrol/pentagi" target="_blank" rel="noopener noreferrer" className="text-accent-600 underline">
              PentAGI
            </a>{' '}
            (Copyright © 2025 PentAGI Development Team) projesinden yararlanmaktadır.
          </p>
          <pre className="mt-4 overflow-x-auto rounded-card bg-brand-50/60 p-4 text-xs leading-relaxed text-ink-soft">
{`MIT License

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
SOFTWARE.`}
          </pre>
        </div>
      </section>

      <p className="mt-8 text-sm text-ink-soft">
        <Link href="/hakkimizda" className="text-accent-600 underline">← Hakkımızda</Link>
      </p>
    </main>
  );
}
