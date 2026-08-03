import { COMPANY } from '../../lib/company';

export const metadata = { title: 'İletişim — CyberTestify' };

export default function Page() {
  return (
    <main className="container-page max-w-2xl py-14">
      <h1 className="text-3xl font-extrabold text-brand">İletişim</h1>
      <p className="mt-3 text-ink-soft">
        Sorularınız, destek talepleriniz ve sözleşmesel bildirimler için bize aşağıdaki kanallardan ulaşabilirsiniz.
      </p>

      <div className="mt-8 space-y-4 rounded-card border border-line bg-brand-50/40 p-6 text-sm leading-relaxed text-ink-soft">
        <div>
          <div className="text-xs font-bold uppercase tracking-wide text-brand-500">Ticari Unvan</div>
          <div className="text-base font-semibold text-brand">{COMPANY.legalName}</div>
        </div>
        <div>
          <div className="text-xs font-bold uppercase tracking-wide text-brand-500">Adres</div>
          <div>{COMPANY.address}</div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <div className="text-xs font-bold uppercase tracking-wide text-brand-500">E-posta</div>
            <a href={`mailto:${COMPANY.email}`} className="text-accent-600 underline">
              {COMPANY.email}
            </a>
          </div>
          <div>
            <div className="text-xs font-bold uppercase tracking-wide text-brand-500">Telefon</div>
            <a href={`tel:${COMPANY.phone.replace(/\s/g, '')}`} className="text-accent-600 underline">
              {COMPANY.phone}
            </a>
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-3 border-t border-line pt-4">
          <div>
            <div className="text-xs font-bold uppercase tracking-wide text-brand-500">Vergi Dairesi / No</div>
            <div>
              {COMPANY.taxOffice} / {COMPANY.taxNo}
            </div>
          </div>
          <div>
            <div className="text-xs font-bold uppercase tracking-wide text-brand-500">Ticaret Sicil No</div>
            <div>{COMPANY.ticaretSicilNo}</div>
          </div>
          <div>
            <div className="text-xs font-bold uppercase tracking-wide text-brand-500">MERSİS No</div>
            <div>{COMPANY.mersisNo}</div>
          </div>
        </div>
      </div>

      <p className="mt-6 text-xs text-ink-muted">
        Destek taleplerine genellikle 1 iş günü içinde dönüş yapılır. Ödeme ve faturalandırmaya ilişkin
        sorularınız için de aynı e-posta adresini kullanabilirsiniz.
      </p>
    </main>
  );
}
