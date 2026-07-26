# Pentest SaaS — MVP İskeleti

Bu depo, konuşmada tasarladığımız akışın (domain doğrulama → paket seçimi →
ödeme → PentAGI ile otomatik tarama → şifreli rapor teslimi) çalışan bir
iskeletidir. `backend/` PentAGI'nin GraphQL API'sine gerçek şemasından
(vxcontrol/pentagi `backend/pkg/graph/schema.graphqls`) doğrulanmış alanlarla
konuşur; `frontend/` müşterinin gördüğü tek yüzeydir — müşteri PentAGI'ye
hiçbir zaman doğrudan erişmez.

## Önemli: EULA bulgusu

`LICENSE` MIT'tir ve ticari kullanıma izin verir. Ancak repo ayrıca bir
`EULA.md` içeriyor ve bu, "yazılımı veya türevlerini bu anlaşmada belirtilen
şekiller dışında alt lisanslama/satma/dağıtma" konusunda kısıtlayıcı bir dil
kullanıyor (md dosyasının orijinali için bkz. klonlanan `pentagi/EULA.md`).
Bizim modelimiz — yazılımı kendi sunucumuzda barındırıp, yazılımın kendisini
değil sadece ürettiği raporu/servisi satmak — bu tür EULA'larda genellikle
sorun teşkil etmez (Cobalt, Astra gibi rakiplerin de temelde açık kaynak
tarama motorları üzerine kurulu ticari servisler sunması bunu destekliyor).
Yine de EULA'nın "sublicense/sell/distribute" maddesindeki belirsiz dil ve
NOTICE dosyasındaki VXControl Cloud SDK / AGPL referansı nedeniyle, ölçek
büyümeden önce bir avukata EULA'yı tek seferlik okutmanı öneririm — özellikle
VXControl'ün ücretli "Cloud Services" (threat intel, premium özellikler)
kısmına HİÇ girmeyip sadece temel self-hosted tarama motorunu kullanman,
riski büyük ölçüde azaltıyor.

## Mimari

```
Müşteri → frontend (Next.js) → backend (Node/Express, bu repo)
                                   │
                                   ├── kendi Postgres DB'si (Prisma) — müşteri/sipariş/rapor
                                   ├── iyzico (ödeme)
                                   └── PentAGI GraphQL API (servis token'ı ile, private network)
                                          └── PentAGI kendi Postgres/MinIO'sunu kullanır (dokunulmaz)
```

## Kurulum (geliştirme ortamı)

### 1) PentAGI tarafı
- Sen zaten Docker ile ayağa kaldırdın. **Önce `admin@pentagi.com` / `admin`
  şifresini değiştir.**
- PentAGI admin panelinden **API Tokens** bölümüne gidip bu backend için
  sınırlı yetkili bir servis token'ı üret; `backend/.env`'deki
  `PENTAGI_SERVICE_TOKEN`'a koy.
- `PENTAGI_GRAPHQL_URL`'i kendi instance'ının adresine ayarla — bunu **asla**
  internete açık bırakma, sadece backend'in erişebildiği private network'te
  tut.

### 2) Backend
```bash
cd backend
cp .env.example .env   # değerleri doldur
npm install
npx prisma migrate dev --name init
npm run dev             # API sunucusu (port 4000)
npm run worker          # AYRI bir terminalde — flow durumlarını izleyen poller
```
`npx tsc --noEmit` bu oturumda hatasız geçti; temel tip güvenliği doğrulandı.

### 3) Frontend
```bash
cd frontend
cp .env.local.example .env.local
npm install
npm run dev              # http://localhost:3000
```
(Bu oturumda frontend için `npm install`/build çalıştırılmadı — Next.js
kurulumu zaman aldığından, teslim önceliği backend'in doğrulanmasına
verildi. İlk `npm run dev`'de küçük tip hataları çıkarsa normal, hızlıca
düzeltilir.)

## Bilinçli olarak TAMAMLANMAMIŞ / TODO bırakılan yerler

Bunlar rastgele eksik değil — ya senin karar vermen gereken ya da gerçek
kimlik bilgisi gerektiren yerler:

1. **iyzico gerçek entegrasyonu** (`backend/src/services/payment/iyzico.ts`) —
   şu an iskelet; gerçek `iyzipay` SDK çağrıları ve merchant kimlik
   bilgilerinle tamamlanmalı.
2. **BYOK akışı** (`orchestrator.ts` içindeki `TODO`) — müşterinin kendi
   API anahtarıyla PentAGI'de geçici bir Provider profili oluşturup iş
   bitince silme mantığı henüz yazılmadı.
3. **Rapor teslim e-postası** — `worker.ts` şu an erişim şifresini sadece
   konsola yazıyor; gerçek bir e-posta servisine (SendGrid/Postmark/SES)
   bağlanıp bu şifreyi rapor linkinden AYRI bir e-postayla göndermen lazım.
4. **Paket fiyatları ve `maxToolCalls` değerleri** (`scanPackages.ts`) —
   örnek değerler. Opus denemende kaç adım/tool-call harcandığını
   `usageStatsByFlow` / `toolcallsStatsByFlow` sorgularıyla PentAGI'den
   çekip gerçek maliyeti hesapla, üzerine kâr marjı koy.
5. **TLS/domain** — hem PentAGI hem bu backend/frontend gerçek bir domain +
   Let's Encrypt sertifikasıyla yayına alınmalı, self-signed sertifikayla
   değil.
6. **Tool-call tavanı bir "hard limit" değil** — PentAGI'nin API'sinde
   flow bazlı tavan alanı yok, sadece instance geneli `.env` değişkeni var.
   Bu yüzden `worker.ts` polling ile (varsayılan 8 saniyede bir) sayacı
   izleyip aşımda `stopFlow` çağırıyor — küçük bir gecikmeyle çalışan
   "yumuşak" bir tavan. Daha sıkı kontrol istersen polling aralığını
   kısaltabilirsin.

## Deploy

Bu oturum, bilgisayarındaki PentAGI Docker kurulumuna doğrudan erişemedi
(cihaz köprüsü bağlı değildi), bu yüzden kodu senin ortamına canlı olarak
bağlayıp test edemedim. Kod burada tamamen hazır — kendi sunucunda (ya da
Claude masaüstü uygulamasını bu oturuma bağlayıp) yukarıdaki adımlarla
çalıştırabilirsin. İstersen bir sonraki oturumda cihaz köprüsünü bağlayıp
gerçek PentAGI instance'ına karşı uçtan uca test edebiliriz.
