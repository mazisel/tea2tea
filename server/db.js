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
  },
];

function initializeDatabase() {
  createTables();
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

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      description TEXT,
      price REAL NOT NULL CHECK(price >= 0),
      image_url TEXT,
      grams INTEGER DEFAULT 0,
      stock INTEGER DEFAULT 0,
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
  db.prepare('CREATE INDEX IF NOT EXISTS idx_blends_user ON blends(user_id)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_blend_items_blend ON blend_items(blend_id)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_blend_comments_blend ON blend_comments(blend_id)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_subscriptions_customer ON subscriptions(customer_id)').run();
}

function getDefaultAdminCredentials() {
  const username = process.env.ADMIN_USERNAME || 'admin';
  const password = process.env.ADMIN_PASSWORD;

  if (!password || password.trim().length < 6) {
    throw new Error('ADMIN_PASSWORD environment variable must be set and at least 6 characters.');
  }

  return { username, password: password.trim() };
}

function seedDefaults() {
  const settingsStmt = db.prepare('INSERT OR IGNORE INTO site_settings (key, value) VALUES (@key, @value)');
  DEFAULT_SETTINGS.forEach((setting) => settingsStmt.run(setting));

  const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get().count;
  if (productCount === 0) {
    const insertProduct = db.prepare(`
      INSERT INTO products (name, slug, description, price, image_url, grams, stock, is_active)
      VALUES (@name, @slug, @description, @price, @image_url, @grams, @stock, @is_active)
    `);
    DEFAULT_PRODUCTS.forEach((product) => insertProduct.run(product));
  }

  const adminCount = db.prepare('SELECT COUNT(*) as count FROM admin_users').get().count;
  if (adminCount === 0) {
    const defaultAdmin = getDefaultAdminCredentials();
    const passwordHash = bcrypt.hashSync(defaultAdmin.password, 10);
    db.prepare('INSERT INTO admin_users (username, password_hash) VALUES (?, ?)').run(
      defaultAdmin.username,
      passwordHash,
    );
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
