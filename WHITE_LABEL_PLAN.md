# White-label Altyapısı — Plan (İş 4)

Amaç: Ajanslara **markasız** (kendi logosu/rengi ile) rapor + API satmak. Bu belge
gereken değişiklikleri ve efor tahminini özetler. **Kod yazılmadı** — sonraki promptun konusu.

---

## 1. Rapor şablonu parametrikleştirme

Mevcut PDF şablonu (`backend/src/services/pdf.ts`) markayı **hardcoded** içerir. White-label
için şu öğelerin **tenant (ajans) bazlı config**'ten gelmesi gerekir:

| Öğe | Şu an (hardcoded) | White-label'de |
|-----|-------------------|----------------|
| Logo | `LOGO_SVG` (inline kalkan SVG) | Ajansın logosu (yüklenen PNG/SVG → data-URI) |
| Marka adı | "Cyber**Testify**" (banner) | Ajans adı |
| Ana renk | teal `#123F3A` (CSS'te sabit) | Ajans birincil rengi (tema değişkeni) |
| Vurgu rengi | amber `#F5A623` | Ajans vurgu rengi |
| Tagline | "Otomatik Güvenlik Tarama Raporu" | Ajans metni (opsiyonel) |
| Footer | "Yapay zeka üretimi… Gizlidir." | Ajans + yasal metin (yasal uyarı KALIR, marka değişir) |
| Dosya adı | `cybertestify-rapor-…pdf` | `<ajans-slug>-rapor-…pdf` |

**Mevcut esneklik:** Şablon zaten tek fonksiyon (`buildHtml`) + lokalize sözlük (`L`) +
tema-farkında CSS. Renkler CSS'te birkaç sabit hex; **CSS değişkenlerine** (`--brand`,
`--accent`) çevrilip `buildHtml`'e `theme` parametresi eklemek nispeten temiz. Logo zaten
inline SVG → data-URI ile değiştirilebilir. **Zorluk düşük-orta.**

**Gerekli değişiklik:**
- `renderReportPdf(md, meta, opts)` imzasına `branding?: BrandingConfig` ekle
  (`{ name, logoDataUri, primaryColor, accentColor, tagline?, footerNote? }`).
- CSS'teki sabit hex'leri `:root` değişkenlerine çevir; branding varsa override et.
- Branding yoksa mevcut CyberTestify varsayılanı (geri uyumlu).
- Yasal uyarı metni (AI-üretimi, kapsam, resmi-değil) **her zaman kalır** — bu hukuki
  zorunluluk, white-label'de silinemez (sadece ajans markası eklenir).

## 2. Ajans hesabı kavramı

Normal `Customer`'dan farkları:

| Konu | Normal müşteri | Ajans hesabı |
|------|----------------|--------------|
| Kullanıcı | Tek | **Çoklu kullanıcı** (ajans ekibi) — yeni `AgencyUser` + rol |
| Kimlik | Panel (JWT) | Panel + **API key** (programatik erişim) |
| Faturalama | Tarama başına / kredi | **Toptan** (aylık/kredi havuzu, indirimli) — kredi sistemi (İş 2) buna temel |
| Marka | CyberTestify | Kendi `Branding` kaydı |
| Rapor teslim | Panel + e-posta | API ile çekme + kendi müşterisine iletme |

**Veri modeli (öneri):**
- `Agency { id, name, slug, brandingId, creditBalance, apiKeyHash, createdAt }`
- `AgencyUser { id, agencyId, email, role }` (çoklu kullanıcı)
- `Branding { id, name, logoDataUri, primaryColor, accentColor, tagline?, footerNote? }`
- `Customer.agencyId?` (opsiyonel — bir müşteri bir ajansa bağlıysa)
- Order → hangi ajans/branding ile üretildiği (rapor render'ında kullanılır)

**API katmanı:** API-key auth middleware (mevcut JWT'den ayrı), rate-limit, ajansın
kendi domain'leri/taramaları/raporları için REST uçları (mevcut route'ların API-key
versiyonu). Kredi sistemi (İş 2) toptan faturalama temelini zaten sağlıyor.

## 3. Kabaca efor tahmini

| Parça | Efor |
|-------|------|
| Rapor şablonu parametrikleştirme (branding) | **Küçük-Orta** (~1-2 gün) — CSS değişkenleri + logo data-URI + imza |
| Branding CRUD + yükleme (logo/renk) | **Küçük** (~1 gün) |
| Ajans hesabı + AgencyUser + roller | **Orta** (~2-3 gün) — yeni modeller, migration, auth |
| API-key auth + programatik REST uçları | **Orta-Büyük** (~3-5 gün) — ayrı auth, rate-limit, dokümante uçlar, güvenlik |
| Toptan faturalama (kredi havuzu üstüne) | **Küçük** (İş 2 kredi sistemi temeli var) |
| **Toplam** | **Orta-Büyük** (~1.5-2 hafta) |

**En hızlı MVP yolu:** (a) rapor branding parametrikleştirme + (b) tek-ajans-tek-branding +
(c) mevcut kredi sistemini toptan havuz olarak kullanmak. API-key katmanı + çoklu kullanıcı
ikinci faz olarak ertelenebilir. Bu MVP ~3-4 gün.

**Not:** Bu bir PLANDIR; kod yazılmadı. Uygulama ayrı bir promptla gelecek.
