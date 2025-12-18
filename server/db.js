const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const dbFilePath = path.join(__dirname, '..', 'data', 'store.sqlite');

// Ensure the data directory exists before accessing the database file
const dataDir = path.dirname(dbFilePath);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(dbFilePath);
db.pragma('foreign_keys = ON');

const DEFAULT_SETTINGS = [
  { key: 'site_name', value: 'Tea2Tea' },
  { key: 'hero_title', value: 'Çayınızı Seçin, Keyfini Çıkarın' },
  { key: 'hero_subtitle', value: 'En özel çay karışımları, sadece birkaç tık uzağınızda.' },
  { key: 'contact_email', value: 'destek@tea2tea.com' },
  { key: 'contact_phone', value: '+90 555 123 45 67' },
  {
    key: 'store_banner',
    value: 'https://images.unsplash.com/photo-1484981137412-0ea37f975c85?auto=format&fit=crop&w=1200&q=80',
  },
  { key: 'logo_url', value: '/logo.png' },
  { key: 'favicon_url', value: 'https://fav.farm/🍵' },
  { key: 'primary_color', value: '#0071e3' },
  { key: 'secondary_color', value: '#f5f5f7' },
  { key: 'theme_color', value: '#0b0c0f' },
  // SMTP Settings
  { key: 'smtp_host', value: process.env.SMTP_HOST || 'smtp.example.com' },
  { key: 'smtp_port', value: process.env.SMTP_PORT || '587' },
  { key: 'smtp_user', value: process.env.SMTP_USER || 'user' },
  { key: 'smtp_pass', value: process.env.SMTP_PASS || 'pass' },
  { key: 'smtp_secure', value: process.env.SMTP_SECURE === 'true' ? '1' : '0' },
  // PayTR Settings
  { key: 'paytr_merchant_id', value: process.env.PAYTR_MERCHANT_ID || '' },
  { key: 'paytr_merchant_key', value: process.env.PAYTR_MERCHANT_KEY || '' },
  { key: 'paytr_merchant_salt', value: process.env.PAYTR_MERCHANT_SALT || '' },
  { key: 'paytr_test_mode', value: process.env.PAYTR_TEST_MODE || '1' },
  { key: 'paytr_debug', value: process.env.PAYTR_DEBUG || '0' },

  // --- FRONTEND CONTENT DEFAULTS ---
  // Hero
  { key: 'hero_eyebrow', value: 'Yeni Nesil Çay Deneyimi' },
  { key: 'hero_btn_text', value: 'Koleksiyonu İncele' },
  { key: 'hero_btn_link', value: '#collection' },
  { key: 'hero_btn2_text', value: "Tea Lab'e Katıl" },
  { key: 'hero_btn2_link', value: '/tea-lab' },
  // Hero Metrics
  { key: 'hero_metric1_val', value: '500+' },
  { key: 'hero_metric1_label', value: 'mutlu çay sever' },
  { key: 'hero_metric2_val', value: '36' },
  { key: 'hero_metric2_label', value: 'özel harman' },
  { key: 'hero_metric3_val', value: '24s' },
  { key: 'hero_metric3_label', value: 'teslimat garantisi' },

  // Collection Section
  { key: 'show_collection', value: '1' },
  { key: 'collection_eyebrow', value: 'Tea2Tea Koleksiyonu' },
  { key: 'collection_title', value: 'Özenle hazırlanan premium harmanlar' },
  { key: 'collection_desc', value: 'Minimalist sunum, yoğun aroma ve rafine bir deneyim. Her bir harman; sürdürülebilir çiftliklerden seçilen yaprakların modern yorumudur.' },

  // Experience Section
  { key: 'show_experience', value: '1' },
  { key: 'exp_eyebrow', value: 'Tea2Tea Manifestosu' },
  { key: 'exp_title', value: 'Minimalist. Rafine. Zamansız.' },
  { key: 'exp_desc', value: 'İlhamımız Kuzey Avrupa tasarım dili ve Uzak Doğu çay seremonisi. Sade çizgiler ve kusursuz harmanlar ile çay ritüelinizi yeniden yorumluyoruz.' },
  // Experience Points
  { key: 'exp_p1_title', value: 'Kurumsal kalite, butik yaklaşım' },
  { key: 'exp_p1_desc', value: 'Her siparişte; tadım ekibi onayı, aromalar arası denge ve premium paketleme standarttır.' },
  { key: 'exp_p2_title', value: 'Sürdürülebilir üretim süreci' },
  { key: 'exp_p2_desc', value: 'Karbon ayak izini minimize eden çiftliklerle çalışıyor, doğaya saygılı bir üretim zinciri kuruyoruz.' },
  { key: 'exp_p3_title', value: 'Şeffaf ve hızlı teslimat' },
  { key: 'exp_p3_desc', value: 'Siparişiniz 24 saat içinde hazırlanır, kapınıza kadar takip edilebilir şekilde ulaşır.' },

  // Tea Lab Section
  { key: 'show_tealab', value: '1' },
  { key: 'tealab_eyebrow', value: 'Tea Lab' },
  { key: 'tealab_title', value: 'Her ay yeni bir imza harman keşfedin.' },
  { key: 'tealab_desc', value: 'Tea Lab aboneliğiyle limitli üretim koleksiyonlara erken erişim, deneyim kutuları ve özel etkinlik davetleri alın.' },
  { key: 'tealab_btn_text', value: "Tea Lab'e Katıl — 599 ₺ / ay" },
  { key: 'tealab_btn_link', value: '/tea-lab' },
  // Tea Lab Benefits
  { key: 'tealab_benefit1', value: 'Her ay 100 g seçkin Tea Lab harmanı kapınızda.' },
  { key: 'tealab_benefit2', value: 'Öncelikli lansman erişimi ve özel tadım etkinlikleri.' },
  { key: 'tealab_benefit3', value: 'Sadece abonelere özel sürpriz aksesuar ve notlar.' },

  // Footer
  { key: 'footer_desc', value: 'Seçkin çay koleksiyonumuzu keşfedin, misafirlerinize keyif dolu anlar yaşatın.' },

  // Pages
  // About
  { key: 'about_title', value: 'Hakkımızda' },
  { key: 'about_content', value: '<p>Tea2Tea, çay tutkusunu modern bir deneyimle buluşturmak için yola çıktı. 2024 yılında kurulan markamız, dünyanın dört bir yanından özenle seçilen çay yapraklarını, usta harmanlayıcıların dokunuşuyla benzersiz lezzetlere dönüştürüyor.</p><p>Sürdürülebilirlik ve kalite odaklı yaklaşımımızla, her yudumda doğallığı ve saflığı hissetmenizi amaçlıyoruz.</p>' },
  // Contact
  { key: 'contact_title', value: 'İletişim' },
  { key: 'contact_content', value: '<p>Sorularınız, önerileriniz veya iş birlikleri için bize her zaman ulaşabilirsiniz.</p>' },
  { key: 'contact_address', value: 'Bağdat Caddesi No: 123, Kadıköy, İstanbul' },
  { key: 'contact_map_url', value: '' },
];

const DEFAULT_PRODUCTS = [
  {
    name: 'Yeşil Çay Harmanı',
    slug: 'yesil-cay-harmani',
    description: 'Taze yapraklardan elde edilen, hafif ve ferahlatıcı bir yeşil çay karışımı.',
    price: 189.9,
    image_url: 'https://images.unsplash.com/photo-1466978913421-dad2ebd01d17?auto=format&fit=crop&w=800&q=80',
    stock: 42,
    is_active: 1,
    grams: 250,
    category: 'Yeşil Çay',
  },
  {
    name: 'Earl Grey',
    slug: 'earl-grey',
    description: 'Bergamot aromasıyla zenginleştirilmiş klasik Earl Grey çayı.',
    price: 164.5,
    image_url: 'https://images.unsplash.com/photo-1517686469429-8bdb88b9f907?auto=format&fit=crop&w=800&q=80',
    stock: 34,
    is_active: 1,
    grams: 200,
    category: 'Siyah Çay',
  },
  {
    name: 'Adaçayı',
    slug: 'adacayi',
    description: 'Doğal olarak kurutulmuş yapraklardan hazırlanan rahatlatıcı adaçayı.',
    price: 129.9,
    image_url: 'https://images.unsplash.com/photo-1466978912941-2e3e46889a6a?auto=format&fit=crop&w=800&q=80',
    stock: 56,
    is_active: 1,
    grams: 150,
    category: 'Bitki Çayı',
  },
];

function initializeDatabase() {
  createTables();
  migrateCategories();
  seedDefaults();
}

function createTables() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS site_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS customers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS customer_addresses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_id INTEGER NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('shipping','billing')),
      title TEXT,
      recipient_name TEXT NOT NULL,
      phone TEXT,
      address_line TEXT NOT NULL,
      district TEXT,
      city TEXT NOT NULL,
      postal_code TEXT,
      country TEXT DEFAULT 'Türkiye',
      notes TEXT,
      is_default INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS subscription_payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_id INTEGER NOT NULL,
      plan TEXT NOT NULL,
      price REAL NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      merchant_oid TEXT NOT NULL UNIQUE,
      paytr_token TEXT,
      payment_provider TEXT,
      payment_payload TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      description TEXT,
      price REAL NOT NULL CHECK(price >= 0),
      image_url TEXT,
      grams INTEGER DEFAULT 0,
      stock INTEGER DEFAULT 0,
      category TEXT DEFAULT 'Genel',
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_number TEXT NOT NULL UNIQUE,
      customer_name TEXT NOT NULL,
      customer_email TEXT NOT NULL,
      customer_phone TEXT,
      customer_address TEXT,
      customer_city TEXT,
      customer_notes TEXT,
      total_amount REAL NOT NULL CHECK(total_amount >= 0),
      discount_id INTEGER REFERENCES discounts(id),
      discount_code TEXT,
      discount_amount REAL NOT NULL DEFAULT 0 CHECK(discount_amount >= 0),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      customer_id INTEGER,
      status TEXT NOT NULL DEFAULT 'pending',
      payment_provider TEXT,
      payment_reference TEXT,
      payment_payload TEXT,
      paid_at DATETIME,
      shipped_at DATETIME,
      delivered_at DATETIME,
      FOREIGN KEY(customer_id) REFERENCES customers(id)
    );

    CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      product_name TEXT NOT NULL,
      unit_price REAL NOT NULL CHECK(unit_price >= 0),
      quantity INTEGER NOT NULL CHECK(quantity > 0),
      FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
      FOREIGN KEY(product_id) REFERENCES products(id)
    );

    CREATE TABLE IF NOT EXISTS discounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT NOT NULL UNIQUE,
      description TEXT,
      type TEXT NOT NULL CHECK(type IN ('percentage','amount')),
      value REAL NOT NULL CHECK(value >= 0),
      minimum_order_total REAL NOT NULL DEFAULT 0 CHECK(minimum_order_total >= 0),
      usage_limit INTEGER,
      used_count INTEGER NOT NULL DEFAULT 0,
      start_date DATETIME,
      end_date DATETIME,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS blends (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      total_grams INTEGER NOT NULL CHECK(total_grams > 0),
      is_shared INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES customers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS blend_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      blend_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      grams INTEGER NOT NULL CHECK(grams > 0),
      FOREIGN KEY(blend_id) REFERENCES blends(id) ON DELETE CASCADE,
      FOREIGN KEY(product_id) REFERENCES products(id)
    );

    CREATE TABLE IF NOT EXISTS blend_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      blend_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      rating INTEGER CHECK(rating BETWEEN 1 AND 5),
      comment TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(blend_id) REFERENCES blends(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES customers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_id INTEGER NOT NULL,
      plan TEXT NOT NULL,
      price REAL NOT NULL CHECK(price >= 0),
      gram_amount INTEGER NOT NULL CHECK(gram_amount > 0),
      status TEXT NOT NULL DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
    );
  `);

  try {
    db.prepare('ALTER TABLE orders ADD COLUMN customer_id INTEGER REFERENCES customers(id)').run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare("ALTER TABLE orders ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'").run();
    db.prepare("UPDATE orders SET status = 'processing'").run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare('ALTER TABLE orders ADD COLUMN payment_provider TEXT').run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare('ALTER TABLE orders ADD COLUMN payment_reference TEXT').run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare('ALTER TABLE orders ADD COLUMN payment_payload TEXT').run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare('ALTER TABLE orders ADD COLUMN paid_at DATETIME').run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare('ALTER TABLE orders ADD COLUMN shipped_at DATETIME').run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare('ALTER TABLE orders ADD COLUMN delivered_at DATETIME').run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare('ALTER TABLE orders ADD COLUMN discount_id INTEGER REFERENCES discounts(id)').run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare('ALTER TABLE orders ADD COLUMN discount_code TEXT').run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare('ALTER TABLE orders ADD COLUMN discount_amount REAL NOT NULL DEFAULT 0').run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare('ALTER TABLE orders ADD COLUMN shipping_address_snapshot TEXT').run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare('ALTER TABLE orders ADD COLUMN billing_address_snapshot TEXT').run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare('ALTER TABLE customers ADD COLUMN phone TEXT').run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare('ALTER TABLE products ADD COLUMN grams INTEGER DEFAULT 0').run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare("ALTER TABLE products ADD COLUMN category TEXT DEFAULT 'Genel'").run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  try {
    db.prepare('ALTER TABLE subscriptions ADD COLUMN gram_amount INTEGER DEFAULT 100').run();
  } catch (err) {
    if (String(err.message).includes('no such table')) {
      // Table will be created above on next init
    } else if (!String(err.message).includes('duplicate column')) {
      throw err;
    }
  }

  db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_email ON customers(email)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_customer_addresses_customer ON customer_addresses(customer_id)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_customer_addresses_type ON customer_addresses(type)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_subscription_payments_customer ON subscription_payments(customer_id)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_subscription_payments_status ON subscription_payments(status)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_blends_user ON blends(user_id)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_blend_items_blend ON blend_items(blend_id)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_blend_comments_blend ON blend_comments(blend_id)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_subscriptions_customer ON subscriptions(customer_id)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_discounts_active ON discounts(is_active)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_discounts_code ON discounts(code)').run();
  db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_discounts_code ON discounts(code)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_products_category ON products(category)').run();
}

function migrateCategories() {
  // Create categories table if not exists
  db.exec(`
    CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      slug TEXT NOT NULL UNIQUE,
      description TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Migrate existing categories from products
  const products = db.prepare('SELECT DISTINCT category FROM products WHERE category IS NOT NULL').all();
  const insertCategory = db.prepare('INSERT OR IGNORE INTO categories (name, slug) VALUES (?, ?)');

  products.forEach(p => {
    if (p.category && p.category.trim() !== '') {
      const name = p.category.trim();
      const slug = name.toLowerCase().replace(/ /g, '-').replace(/[^\w-]+/g, '');
      insertCategory.run(name, slug);
    }
  });
}

function getDefaultAdminCredentials() {
  const username = process.env.ADMIN_USERNAME || 'admin';
  const password = process.env.ADMIN_PASSWORD;

  if (!password || password.trim().length < 10) {
    console.error('DEBUG: ADMIN_PASSWORD check failed.');
    console.error('DEBUG: ADMIN_USERNAME:', username);
    console.error('DEBUG: ADMIN_PASSWORD value type:', typeof password);
    console.error('DEBUG: ADMIN_PASSWORD length:', password ? password.length : 'null/undefined');
    if (password) console.error('DEBUG: ADMIN_PASSWORD trimmed length:', password.trim().length);

    throw new Error('ADMIN_PASSWORD environment variable must be set and at least 10 characters.');
  }

  return { username, password: password.trim() };
}

function seedDefaults() {
  const settingsStmt = db.prepare('INSERT OR IGNORE INTO site_settings (key, value) VALUES (@key, @value)');
  DEFAULT_SETTINGS.forEach((setting) => settingsStmt.run(setting));

  const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get().count;
  if (productCount === 0) {
    const insertProduct = db.prepare(`
      INSERT INTO products (name, slug, description, price, image_url, grams, stock, category, is_active)
      VALUES (@name, @slug, @description, @price, @image_url, @grams, @stock, @category, @is_active)
    `);
    DEFAULT_PRODUCTS.forEach((product) => insertProduct.run(product));
  }

  const defaultAdmin = getDefaultAdminCredentials();
  const existingAdmin = db
    .prepare('SELECT id, username, password_hash AS passwordHash FROM admin_users WHERE username = ?')
    .get(defaultAdmin.username);

  const passwordHash = bcrypt.hashSync(defaultAdmin.password, 10);

  if (!existingAdmin) {
    const adminCount = db.prepare('SELECT COUNT(*) as count FROM admin_users').get().count;
    if (adminCount === 0) {
      db.prepare('INSERT INTO admin_users (username, password_hash) VALUES (?, ?)').run(
        defaultAdmin.username,
        passwordHash,
      );
    } else {
      db.prepare('INSERT OR IGNORE INTO admin_users (username, password_hash) VALUES (?, ?)').run(
        defaultAdmin.username,
        passwordHash,
      );
    }
  } else {
    if (!bcrypt.compareSync(defaultAdmin.password, existingAdmin.passwordHash)) {
      db.prepare('UPDATE admin_users SET password_hash = ? WHERE id = ?').run(passwordHash, existingAdmin.id);
    }
  }
}

function getSetting(key) {
  return db.prepare('SELECT value FROM site_settings WHERE key = ?').get(key)?.value ?? null;
}

function setSetting(key, value) {
  db.prepare('INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(
    key,
    value,
  );
}

function getAllSettings() {
  const rows = db.prepare('SELECT key, value FROM site_settings').all();
  return rows.reduce((acc, row) => {
    acc[row.key] = row.value;
    return acc;
  }, {});
}

module.exports = {
  db,
  initializeDatabase,
  getSetting,
  getAllSettings,
  setSetting,
  getDefaultAdminCredentials,
};
