# Tea2Tea – Minimal E-Ticaret Uygulaması

Tea2Tea; kayıt sistemine ihtiyaç duymayan, tek yöneticili, küçük ölçekli bir e-ticaret vitrini ve yönetim panelidir. Ürün, sipariş ve site ayarları tamamen admin panelinden yönetilir.

## Özellikler

- 🚀 **Mağaza**
  - Ürün listeleme ve detay sayfaları
  - Sepet yönetimi (ürün ekleme, çıkarma, adet güncelleme)
  - Basit ödeme formu ve sipariş oluşturma
  - Sipariş özeti ekranı
- 🔐 **Yönetici Paneli**
  - Yönetici bilgileri `.env` dosyasındaki `ADMIN_USERNAME` ve `ADMIN_PASSWORD` üzerinden belirlenir.
  - Güçlü bir şifre seçip `.env` içinde saklayın; gerekirse admin panelinden güncelleyebilirsiniz.
  - Ürün ekleme/düzenleme/silme, aktif/pasif durumu
  - Sipariş listesi ve detayları
  - Sipariş durumu yönetimi (Hazırlanıyor / Yolda / Teslim Edildi) ve otomatik e-posta bilgilendirmesi
  - Site adı, hero içerikleri, iletişim bilgileri ve görsel ayarları
  - Şifre değiştirme arayüzü
- 👤 **Müşteri Hesabı**
  - Kayıtlı teslimat ve fatura adresleri, profil bilgilerini güncelleme
  - Aktif siparişleri ve teslim edilen sipariş geçmişini ayrı ayrı görüntüleme
  - Sipariş durumları değiştikçe otomatik e-posta ile bilgilendirilme

## Başlarken

### Gereksinimler
- Node.js 18+

### Kurulum

```bash
npm install
npm run dev
```

Sunucu varsayılan olarak `http://localhost:3010` adresinde çalışır.

> ⚠️ `.env` dosyanızda `ADMIN_USERNAME` ve en az 6 karakterlik `ADMIN_PASSWORD` tanımlamadığınız sürece uygulama başlamaz.

### Komutlar
- `npm run dev`: Nodemon ile geliştirme sunucusu
- `npm start`: Production modunda sunucu

## Proje Yapısı

```
tea2tea/
├── server/
│   ├── db.js          # SQLite veritabanı bağlantısı ve seed işlemleri
│   └── index.js       # Express uygulaması ve tüm rotalar
├── views/             # EJS şablonları (mağaza + admin)
├── public/
│   └── css/           # Ortak ve admin stilleri
├── data/
│   └── store.sqlite   # Uygulama çalıştığında oluşturulan veritabanı dosyası
└── README.md
```

## Notlar
- İlk çalıştırmada veritabanı otomatik oluşturulur ve örnek ürünler eklenir.
- Admin paneline giriş yaptıktan sonra “Ayarlar” sekmesinden site içeriğini ve şifrenizi kolayca değiştirebilirsiniz.
- Uygulama SQLite kullandığı için tüm veriler `data/store.sqlite` dosyasında saklanır.

Keyifli kullanımlar! ☕️
