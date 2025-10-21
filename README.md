# Tea2Tea – Minimal E-Ticaret Uygulaması

Tea2Tea; kayıt sistemine ihtiyaç duymayan, tek yöneticili, küçük ölçekli bir e-ticaret vitrini ve yönetim panelidir. Ürün, sipariş ve site ayarları tamamen admin panelinden yönetilir.

## Özellikler

- 🚀 **Mağaza**
  - Ürün listeleme ve detay sayfaları
  - Sepet yönetimi (ürün ekleme, çıkarma, adet güncelleme)
  - Basit ödeme formu ve sipariş oluşturma
  - Sipariş özeti ekranı
- 🔐 **Yönetici Paneli**
  - Varsayılan kullanıcı: `admin`
  - Varsayılan şifre: `admin123` (ilk girişte değiştirmeniz önerilir)
  - Ürün ekleme/düzenleme/silme, aktif/pasif durumu
  - Sipariş listesi ve detayları
  - Site adı, hero içerikleri, iletişim bilgileri ve görsel ayarları
  - Şifre değiştirme arayüzü

## Başlarken

### Gereksinimler
- Node.js 18+

### Kurulum

```bash
npm install
npm run dev
```

Sunucu varsayılan olarak `http://localhost:3010` adresinde çalışır.

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
