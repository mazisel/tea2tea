const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const session = require('express-session');
const methodOverride = require('method-override');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { URLSearchParams } = require('url');
const { db, initializeDatabase, getAllSettings, setSetting } = require('./db');

const app = express();
const PORT = process.env.PORT || 3010;

initializeDatabase();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'tea2tea_super_secret',
    resave: false,
    saveUninitialized: false,
  }),
);
app.use(express.static(path.join(__dirname, '..', 'public')));

const uploadsDir = path.join(__dirname, '..', 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => {
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e6)}`;
    const ext = path.extname(file.originalname || '');
    cb(null, `${unique}${ext}`);
  },
});

const upload = multer({ storage });

const mailer = createMailer();
const MAIL_FROM = process.env.MAIL_FROM || 'Tea2Tea <no-reply@tea2tea.local>';

const SHIPPING_FEE = 99.9;
const FREE_SHIPPING_THRESHOLD = 500;
const TEA_LAB_PLAN = {
  code: 'tea-lab-monthly',
  price: 599,
  grams: 100,
};

const PAYTR_MERCHANT_ID = process.env.PAYTR_MERCHANT_ID || '';
const PAYTR_MERCHANT_KEY = process.env.PAYTR_MERCHANT_KEY || '';
const PAYTR_MERCHANT_SALT = process.env.PAYTR_MERCHANT_SALT || '';
const PAYTR_TEST_MODE = process.env.PAYTR_TEST_MODE === '1' ? 1 : 0;
const PAYTR_NO_INSTALLMENT = process.env.PAYTR_NO_INSTALLMENT === '1' ? 1 : 0;
const PAYTR_MAX_INSTALLMENT = Number(process.env.PAYTR_MAX_INSTALLMENT || 0);
const PAYTR_TIMEOUT_LIMIT = Number(process.env.PAYTR_TIMEOUT_LIMIT || 30);
const PAYTR_CURRENCY = (process.env.PAYTR_CURRENCY || 'TRY').toUpperCase();
const PAYTR_DEBUG_ON = process.env.PAYTR_DEBUG === '1' ? 1 : 0;
const PAYTR_LANG = (process.env.PAYTR_LANG || 'tr').toLowerCase();

const updateProductStockStmt = db.prepare('UPDATE products SET stock = MAX(stock - ?, 0) WHERE id = ?');
const updateOrderPaymentStmt = db.prepare(
  'UPDATE orders SET status = ?, payment_reference = ?, payment_payload = ?, paid_at = CURRENT_TIMESTAMP WHERE id = ?',
);
const updateOrderPayloadStmt = db.prepare('UPDATE orders SET payment_payload = ? WHERE id = ?');
const markOrderFailedStmt = db.prepare('UPDATE orders SET status = ?, payment_payload = ? WHERE id = ?');

app.use((req, res, next) => {
  res.locals.settings = getAllSettings();
  res.locals.isAdmin = Boolean(req.session.isAdmin);
  res.locals.adminUser = req.session.adminUser || null;
  res.locals.currentUser = req.session.user || null;
  res.locals.flash = req.session.flash;
  res.locals.cart = formatCart(req.session.cart);
  res.locals.currentPath = req.path;
  delete req.session.flash;
  next();
});

function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

function calculateCartTotals(cart) {
  const subtotal = cart && typeof cart.totalAmount === 'number' ? cart.totalAmount : 0;
  const qualifiesForFreeShipping = subtotal === 0 || subtotal >= FREE_SHIPPING_THRESHOLD;
  const shippingAmount = qualifiesForFreeShipping ? 0 : SHIPPING_FEE;
  const total = subtotal + shippingAmount;
  return {
    subtotal,
    shippingAmount,
    total,
    qualifiesForFreeShipping,
    remainingForFreeShipping: qualifiesForFreeShipping
      ? 0
      : Math.max(FREE_SHIPPING_THRESHOLD - subtotal, 0),
  };
}

function formatCart(cart) {
  if (!cart || !cart.items) {
    return {
      items: [],
      totalQuantity: 0,
      subtotal: 0,
      shippingAmount: 0,
      totalAmount: 0,
      freeShippingThreshold: FREE_SHIPPING_THRESHOLD,
      shippingFee: SHIPPING_FEE,
      qualifiesForFreeShipping: true,
      remainingForFreeShipping: 0,
    };
  }

  const items = Object.entries(cart.items).map(([key, item]) => ({
    ...item,
    key,
    subtotal: item.price * item.quantity,
  }));
  const totals = calculateCartTotals(cart);
  return {
    items,
    totalQuantity: cart.totalQuantity,
    subtotal: totals.subtotal,
    shippingAmount: totals.shippingAmount,
    totalAmount: totals.total,
    freeShippingThreshold: FREE_SHIPPING_THRESHOLD,
    shippingFee: SHIPPING_FEE,
    qualifiesForFreeShipping: totals.qualifiesForFreeShipping,
    remainingForFreeShipping: totals.remainingForFreeShipping,
  };
}

function getClientIp(req) {
  const headerIp = req.headers['x-forwarded-for'];
  if (typeof headerIp === 'string' && headerIp.length > 0) {
    return headerIp.split(',')[0].trim();
  }
  const socketIp = req.socket?.remoteAddress || req.ip;
  if (!socketIp) {
    return '127.0.0.1';
  }
  // Normalize IPv6 localhost
  if (socketIp === '::1') {
    return '127.0.0.1';
  }
  return socketIp.replace('::ffff:', '');
}

function snapshotCart(cart = {}) {
  const items = Object.values(cart.items || {}).map((item) => ({
    productId: item.productId || null,
    name: item.name,
    price: Number(item.price || 0),
    quantity: Number(item.quantity || 0),
    type: item.type || 'product',
    components: item.components || null,
  }));
  return {
    items,
    totals: {
      totalQuantity: cart.totalQuantity || 0,
      subtotal: cart.totalAmount || 0,
    },
  };
}

function createPaytrBasket(cart, pricing) {
  const basket = [];
  if (cart && cart.items) {
    Object.values(cart.items).forEach((item) => {
      const name = String(item.name || 'Ürün');
      const price = Number(item.price || 0).toFixed(2);
      const quantity = Number(item.quantity || 1);
      basket.push([name, price, quantity]);
    });
  }
  if (pricing.shippingAmount > 0) {
    basket.push(['Kargo', pricing.shippingAmount.toFixed(2), 1]);
  }
  return {
    encoded: Buffer.from(JSON.stringify(basket)).toString('base64'),
    items: basket,
  };
}

function createPaytrToken({
  merchantId,
  merchantKey,
  merchantSalt,
  userIp,
  merchantOid,
  email,
  paymentAmount,
  userBasket,
  noInstallment,
  maxInstallment,
  currency,
  testMode,
}) {
  const hashStr = `${merchantId}${userIp}${merchantOid}${email}${paymentAmount}${userBasket}${noInstallment}${maxInstallment}${currency}${testMode}`;
  const hmac = crypto.createHmac('sha256', merchantKey);
  hmac.update(hashStr + merchantSalt);
  return Buffer.from(hmac.digest()).toString('base64');
}

function requestPaytrToken(payload) {
  return new Promise((resolve, reject) => {
    const postData = new URLSearchParams(payload).toString();
    const req = https.request(
      {
        hostname: 'www.paytr.com',
        path: '/odeme/api/get-token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(postData),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          try {
            const json = JSON.parse(data);
            resolve(json);
          } catch (err) {
            reject(new Error(`PAYTR response parse error: ${data}`));
          }
        });
      },
    );

    req.on('error', (err) => {
      reject(err);
    });

    req.write(postData);
    req.end();
  });
}

function safeJsonParse(value) {
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch (err) {
    return null;
  }
}

function applyStockAdjustments(cartSnapshot) {
  if (!cartSnapshot || !Array.isArray(cartSnapshot.items)) {
    return;
  }
  cartSnapshot.items.forEach((item) => {
    if (!item || item.type === 'blend') return;
    if (!item.productId) return;
    const qty = Number(item.quantity || 0);
    if (qty > 0) {
      updateProductStockStmt.run(qty, item.productId);
    }
  });
}

function buildBaseUrl(req) {
  const forwardedProto = req.headers['x-forwarded-proto'];
  const protocol = forwardedProto ? forwardedProto.split(',')[0] : req.protocol;
  return `${protocol}://${req.get('host')}`;
}

function createPaytrNotifyHash(merchantOid, status, totalAmount) {
  const hmac = crypto.createHmac('sha256', PAYTR_MERCHANT_KEY);
  hmac.update(`${merchantOid}${PAYTR_MERCHANT_SALT}${status}${totalAmount}`);
  return Buffer.from(hmac.digest()).toString('base64');
}

function ensureCart(req) {
  if (!req.session.cart) {
    req.session.cart = { items: {}, totalQuantity: 0, totalAmount: 0 };
  }
  return req.session.cart;
}

function recalcCart(cart) {
  cart.totalQuantity = 0;
  cart.totalAmount = 0;
  Object.values(cart.items).forEach((item) => {
    cart.totalQuantity += item.quantity;
    cart.totalAmount += item.price * item.quantity;
  });
}

function getActiveSubscription(customerId) {
  return db
    .prepare(
      `SELECT id, plan, price, gram_amount AS gramAmount, status, created_at AS createdAt
       FROM subscriptions
       WHERE customer_id = ?
       ORDER BY created_at DESC
       LIMIT 1`,
    )
    .get(customerId);
}

function slugify(text) {
  return text
    .toString()
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9\-ğüşöçıİ]+/g, '')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function generateOrderNumber() {
  const now = new Date();
  const stamp = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(
    now.getDate(),
  ).padStart(2, '0')}`;
  const random = Math.floor(1000 + Math.random() * 9000);
  return `T2T-${stamp}-${random}`;
}

function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) {
    setFlash(req, 'danger', 'Lütfen giriş yapın.');
    return res.redirect('/admin/login');
  }
  next();
}

function requireUser(req, res, next) {
  if (!req.session.user) {
    setFlash(req, 'danger', 'Lütfen giriş yapın.');
    return res.redirect('/login');
  }
  next();
}

function createMailer() {
  if (process.env.SMTP_URL) {
    return nodemailer.createTransport(process.env.SMTP_URL);
  }

  if (process.env.SMTP_HOST) {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth:
        process.env.SMTP_USER && process.env.SMTP_PASS
          ? {
              user: process.env.SMTP_USER,
              pass: process.env.SMTP_PASS,
            }
          : undefined,
    });
  }

  return nodemailer.createTransport({ jsonTransport: true });
}

async function sendEmail(to, subject, html) {
  if (!to) return;
  try {
    await mailer.sendMail({ from: MAIL_FROM, to, subject, html });
  } catch (err) {
    console.error('E-posta gönderimi başarısız:', err.message);
  }
}

function calculateBlendPrice(items) {
  return items.reduce((sum, item) => {
    if (!item.productPrice || !item.productGrams) return sum;
    const pricePerGram = item.productPrice / Math.max(item.productGrams, 1);
    return sum + pricePerGram * item.grams;
  }, 0);
}

// Shop routes
app.get('/', (req, res) => {
  const products = db
    .prepare('SELECT id, name, slug, description, price, grams, image_url AS imageUrl FROM products WHERE is_active = 1 ORDER BY created_at DESC')
    .all();
  res.render('shop/home', { products });
});

app.get('/product/:slug', (req, res) => {
  const product = db
    .prepare(
      'SELECT id, name, slug, description, price, grams, image_url AS imageUrl, stock FROM products WHERE slug = ? AND is_active = 1',
    )
    .get(req.params.slug);

  if (!product) {
    return res.status(404).render('shop/not-found', { message: 'Ürün bulunamadı.' });
  }

  res.render('shop/product', { product });
});

app.post('/cart/add', (req, res) => {
  const { productId, slug, quantity } = req.body;
  const qty = Math.max(1, parseInt(quantity, 10) || 1);

  let product =
    (productId &&
      db
        .prepare('SELECT id, name, slug, price, image_url AS imageUrl FROM products WHERE id = ? AND is_active = 1')
        .get(productId)) ||
    (slug &&
      db
        .prepare('SELECT id, name, slug, price, image_url AS imageUrl FROM products WHERE slug = ? AND is_active = 1')
        .get(slug));

  if (!product) {
    setFlash(req, 'danger', 'Ürün bulunamadı.');
    return res.redirect('back');
  }

  const cart = ensureCart(req);
  const key = String(product.id);
  const existing = cart.items[key];
  if (existing) {
    existing.quantity += qty;
  } else {
    cart.items[key] = {
      key,
      productId: product.id,
      name: product.name,
      slug: product.slug,
      price: product.price,
      quantity: qty,
      imageUrl: product.imageUrl,
    };
  }
  recalcCart(cart);
  setFlash(req, 'success', `${product.name} sepete eklendi.`);
  res.redirect('/cart');
});

app.get('/cart', (req, res) => {
  res.render('shop/cart');
});

app.post('/cart/update', (req, res) => {
  const { quantities } = req.body;
  const cart = ensureCart(req);
  if (quantities && typeof quantities === 'object') {
    Object.entries(quantities).forEach(([productId, value]) => {
      const item = cart.items[productId];
      if (!item) return;
      const qty = Math.max(0, parseInt(value, 10) || 0);
      if (qty <= 0) {
        delete cart.items[productId];
      } else {
        item.quantity = qty;
      }
    });
  }
  recalcCart(cart);
  setFlash(req, 'success', 'Sepet güncellendi.');
  res.redirect('/cart');
});

app.post('/cart/remove', (req, res) => {
  const { key } = req.body;
  const cart = ensureCart(req);
  if (key && cart.items[key]) {
    delete cart.items[key];
    recalcCart(cart);
    setFlash(req, 'success', 'Ürün sepetten çıkarıldı.');
  }
  res.redirect('/cart');
});

app.post('/cart/clear', (req, res) => {
  req.session.cart = { items: {}, totalQuantity: 0, totalAmount: 0 };
  setFlash(req, 'success', 'Sepet temizlendi.');
  res.redirect('/cart');
});

app.get('/checkout', (req, res) => {
  const cart = req.session.cart;
  if (!cart || cart.totalQuantity === 0) {
    setFlash(req, 'danger', 'Önce sepetinize ürün ekleyin.');
    return res.redirect('/');
  }
  res.render('shop/checkout');
});

app.post('/checkout', async (req, res) => {
  const cart = req.session.cart;
  if (!cart || cart.totalQuantity === 0) {
    setFlash(req, 'danger', 'Sepetiniz boş.');
    return res.redirect('/');
  }

  if (!PAYTR_MERCHANT_ID || !PAYTR_MERCHANT_KEY || !PAYTR_MERCHANT_SALT) {
    setFlash(req, 'danger', 'Ödeme sağlayıcısı yapılandırılmadı. Lütfen yönetici ile iletişime geçin.');
    return res.redirect('/checkout');
  }

  const user = req.session.user;
  const { name, email, phone, address, city, notes } = req.body;

  const customerName = (name || user?.name || '').trim();
  const customerEmail = (email || user?.email || '').trim().toLowerCase();
  const customerPhone = (phone || user?.phone || '').trim();
  const customerAddress = (address || '').trim();
  const customerCity = (city || '').trim();
  const customerNotes = (notes || '').trim();

  if (!customerName || !customerEmail || !customerAddress || !customerCity || !customerPhone) {
    setFlash(req, 'danger', 'Lütfen tüm zorunlu alanları doldurun.');
    return res.redirect('/checkout');
  }

  const pricing = calculateCartTotals(cart);
  const paymentAmount = Math.round(pricing.total * 100);
  if (paymentAmount <= 0) {
    setFlash(req, 'danger', 'Ödeme tutarı geçersiz.');
    return res.redirect('/checkout');
  }

  const baseUrl = buildBaseUrl(req);
  const basket = createPaytrBasket(cart, pricing);
  const userIp = getClientIp(req);
  const orderNumber = generateOrderNumber();
  const paytrPhone = customerPhone.replace(/[^\d+]/g, '');

  const tokenPayload = {
    merchant_id: PAYTR_MERCHANT_ID,
    user_ip: userIp,
    merchant_oid: orderNumber,
    email: customerEmail,
    payment_amount: String(paymentAmount),
    user_basket: basket.encoded,
    no_installment: String(PAYTR_NO_INSTALLMENT),
    max_installment: String(PAYTR_MAX_INSTALLMENT),
    user_name: customerName,
    user_address: customerAddress,
    user_city: customerCity,
    user_phone: paytrPhone,
    merchant_ok_url: `${baseUrl}/paytr/return/success`,
    merchant_fail_url: `${baseUrl}/paytr/return/fail`,
    merchant_notify_url: `${baseUrl}/paytr/notify`,
    timeout_limit: String(PAYTR_TIMEOUT_LIMIT),
    currency: PAYTR_CURRENCY,
    test_mode: String(PAYTR_TEST_MODE),
    lang: PAYTR_LANG,
  };
  if (PAYTR_DEBUG_ON) {
    tokenPayload.debug_on = String(PAYTR_DEBUG_ON);
  }

  try {
    tokenPayload.paytr_token = createPaytrToken({
      merchantId: PAYTR_MERCHANT_ID,
      merchantKey: PAYTR_MERCHANT_KEY,
      merchantSalt: PAYTR_MERCHANT_SALT,
      userIp,
      merchantOid: orderNumber,
      email: customerEmail,
      paymentAmount: String(paymentAmount),
      userBasket: basket.encoded,
      noInstallment: String(PAYTR_NO_INSTALLMENT),
      maxInstallment: String(PAYTR_MAX_INSTALLMENT),
      currency: PAYTR_CURRENCY,
      testMode: String(PAYTR_TEST_MODE),
    });
  } catch (err) {
    console.error('PAYTR token generation failed', err);
    setFlash(req, 'danger', 'Ödeme isteği hazırlanırken bir sorun oluştu. Lütfen tekrar deneyin.');
    return res.redirect('/checkout');
  }

  let paytrResponse;
  try {
    paytrResponse = await requestPaytrToken(tokenPayload);
  } catch (err) {
    console.error('PAYTR token request error', err);
    setFlash(req, 'danger', 'PAYTR ödeme servisine ulaşılamadı. Lütfen bir süre sonra tekrar deneyin.');
    return res.redirect('/checkout');
  }

  if (!paytrResponse || paytrResponse.status !== 'success' || !paytrResponse.token) {
    const reason = paytrResponse?.reason || paytrResponse?.message || 'Bilinmeyen bir hata oluştu.';
    console.error('PAYTR token failure', paytrResponse);
    setFlash(req, 'danger', `Ödeme servisinden yanıt alınamadı: ${reason}`);
    return res.redirect('/checkout');
  }

  const paytrToken = paytrResponse.token;
  const cartSnapshot = snapshotCart(cart);
  const paymentPayload = {
    paymentAmount,
    currency: PAYTR_CURRENCY,
    shippingAmount: pricing.shippingAmount,
    subtotal: pricing.subtotal,
    cartSnapshot,
    basket: basket.items,
    testMode: PAYTR_TEST_MODE,
  };

  const insertOrder = db.prepare(`
    INSERT INTO orders (
      order_number,
      customer_name,
      customer_email,
      customer_phone,
      customer_address,
      customer_city,
      customer_notes,
      total_amount,
      customer_id,
      status,
      payment_provider,
      payment_reference,
      payment_payload,
      paid_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertOrderItem = db.prepare(`
    INSERT INTO order_items (
      order_id,
      product_id,
      product_name,
      unit_price,
      quantity
    ) VALUES (?, ?, ?, ?, ?)
  `);

  const transaction = db.transaction(() => {
    const orderResult = insertOrder.run(
      orderNumber,
      customerName,
      customerEmail,
      customerPhone,
      customerAddress,
      customerCity,
      customerNotes || null,
      pricing.total,
      user ? user.id : null,
      'pending',
      'paytr',
      paytrToken,
      JSON.stringify(paymentPayload),
      null,
    );

    Object.values(cart.items).forEach((item) => {
      if (item.type === 'blend' && Array.isArray(item.components)) {
        item.components.forEach((component) => {
          const unitPrice = (component.productPrice / Math.max(component.productGrams, 1)) * component.grams;
          insertOrderItem.run(
            orderResult.lastInsertRowid,
            component.productId,
            `${item.name} • ${component.productName}`,
            parseFloat(unitPrice.toFixed(2)),
            item.quantity,
          );
        });
      } else {
        insertOrderItem.run(orderResult.lastInsertRowid, item.productId, item.name, item.price, item.quantity);
      }
    });

    return orderResult.lastInsertRowid;
  });

  let orderId;
  try {
    orderId = transaction();
  } catch (err) {
    console.error('Failed to create order', err);
    setFlash(req, 'danger', 'Sipariş oluşturulurken hata oluştu. Lütfen tekrar deneyin.');
    return res.redirect('/checkout');
  }

  req.session.awaitingPaymentOrder = orderNumber;
  req.session.pendingPaymentOrderId = orderId;

  res.render('shop/paytr-checkout', {
    orderNumber,
    paytrToken,
    totalAmount: pricing.total,
  });
});

app.get('/order/success/:orderNumber', (req, res) => {
  const { orderNumber } = req.params;
  const order = db
    .prepare(
      `SELECT id, order_number AS orderNumber, customer_name AS customerName, total_amount AS totalAmount,
              created_at AS createdAt, paid_at AS paidAt, status
       FROM orders WHERE order_number = ?`,
    )
    .get(orderNumber);

  if (!order || order.status !== 'paid') {
    return res.status(404).render('shop/not-found', { message: 'Sipariş bulunamadı.' });
  }

  if (req.session.lastOrderNumber !== orderNumber) {
    setFlash(req, 'info', 'Sipariş detaylarına yalnızca son siparişiniz için erişebilirsiniz.');
    return res.redirect('/');
  }

  const items = db
    .prepare(
      'SELECT product_name AS productName, unit_price AS unitPrice, quantity FROM order_items WHERE order_id = ?',
    )
    .all(order.id);

  res.render('shop/order-success', { order, items });
});

app.post('/paytr/notify', async (req, res) => {
  if (!PAYTR_MERCHANT_KEY || !PAYTR_MERCHANT_SALT) {
    console.error('PAYTR notify received but credentials are missing.');
    return res.status(500).send('CONFIGURATION ERROR');
  }

  const payload = req.body || {};
  const merchantOid = payload.merchant_oid;
  const status = payload.status;
  const totalAmount = payload.total_amount || '0';
  const incomingHash = payload.hash;

  if (!merchantOid || !status || !incomingHash) {
    console.warn('PAYTR notify invalid payload', payload);
    return res.status(400).send('INVALID');
  }

  const expectedHash = createPaytrNotifyHash(merchantOid, status, totalAmount);
  if (incomingHash !== expectedHash) {
    console.warn('PAYTR notify hash mismatch', { merchantOid, incomingHash, expectedHash });
    return res.status(400).send('INVALID HASH');
  }

  const order = db
    .prepare(
      `SELECT id, status, customer_email AS customerEmail, customer_name AS customerName,
              payment_payload AS paymentPayload, total_amount AS totalAmount
       FROM orders WHERE order_number = ?`,
    )
    .get(merchantOid);

  if (!order) {
    console.warn('PAYTR notify for unknown order', merchantOid);
    return res.status(404).send('ORDER NOT FOUND');
  }

  const existingPayload = safeJsonParse(order.paymentPayload) || {};
  const mergedPayload = { ...existingPayload, notify: payload };

  try {
    if (status === 'success') {
      if (order.status !== 'paid') {
        applyStockAdjustments(existingPayload.cartSnapshot);
        const paymentReference = payload.payment_id || payload.token || merchantOid;
        updateOrderPaymentStmt.run('paid', paymentReference, JSON.stringify(mergedPayload), order.id);

        if (order.customerEmail) {
          const storeSettings = getAllSettings();
          const storeName = storeSettings.site_name || 'Tea2Tea';
          const items = db
            .prepare(
              'SELECT product_name AS productName, unit_price AS unitPrice, quantity FROM order_items WHERE order_id = ?',
            )
            .all(order.id);
          const orderLines = items
            .map(
              (item) => `<li>${item.productName} x${item.quantity} - ${(item.unitPrice * item.quantity).toFixed(2)} ₺</li>`,
            )
            .join('');
          const shippingLine =
            existingPayload.shippingAmount && existingPayload.shippingAmount > 0
              ? `<p><strong>Kargo:</strong> ${existingPayload.shippingAmount.toFixed(2)} ₺</p>`
              : `<p><strong>Kargo:</strong> Ücretsiz</p>`;
          const mailHtml = `
            <h1>Teşekkürler ${order.customerName}</h1>
            <p>Sipariş numaranız <strong>${merchantOid}</strong>.</p>
            <p>Sipariş özeti:</p>
            <ul>${orderLines}</ul>
            ${shippingLine}
            <p><strong>Toplam:</strong> ${order.totalAmount.toFixed(2)} ₺</p>
          `;
          await sendEmail(order.customerEmail, `${storeName} Sipariş Onayı`, mailHtml);
        }
      } else {
        updateOrderPayloadStmt.run(JSON.stringify(mergedPayload), order.id);
      }
    } else {
      if (order.status !== 'paid') {
        markOrderFailedStmt.run('failed', JSON.stringify(mergedPayload), order.id);
      } else {
        updateOrderPayloadStmt.run(JSON.stringify(mergedPayload), order.id);
      }
    }
  } catch (err) {
    console.error('PAYTR notify processing failed', err);
    return res.status(500).send('ERROR');
  }

  return res.send('OK');
});

function extractPaytrPayload(req) {
  return req.method === 'POST' ? req.body : req.query;
}

app.all('/paytr/return/success', (req, res) => {
  const payload = extractPaytrPayload(req) || {};
  const merchantOid = payload.merchant_oid;
  if (!merchantOid) {
    setFlash(req, 'danger', 'Sipariş numarası alınamadı. Lütfen destek ile iletişime geçin.');
    return res.redirect('/');
  }

  const order = db
    .prepare('SELECT status FROM orders WHERE order_number = ?')
    .get(merchantOid);

  if (!order) {
    setFlash(req, 'danger', 'Sipariş bulunamadı.');
    return res.redirect('/');
  }

  if (order.status === 'paid') {
    req.session.lastOrderNumber = merchantOid;
    req.session.cart = { items: {}, totalQuantity: 0, totalAmount: 0 };
    delete req.session.awaitingPaymentOrder;
    delete req.session.pendingPaymentOrderId;
    setFlash(req, 'success', 'Ödemeniz başarıyla tamamlandı.');
    return res.redirect(`/order/success/${merchantOid}`);
  }

  setFlash(req, 'info', 'Ödeme doğrulanıyor. Lütfen birkaç saniye sonra tekrar deneyin.');
  res.redirect('/');
});

app.all('/paytr/return/fail', (req, res) => {
  const payload = extractPaytrPayload(req) || {};
  const merchantOid = payload.merchant_oid;
  if (merchantOid) {
    const order = db
      .prepare('SELECT id, status, payment_payload AS paymentPayload FROM orders WHERE order_number = ?')
      .get(merchantOid);
    if (order && order.status !== 'paid') {
      const existingPayload = safeJsonParse(order.paymentPayload) || {};
      const mergedPayload = { ...existingPayload, lastFailReturn: payload };
      markOrderFailedStmt.run('failed', JSON.stringify(mergedPayload), order.id);
    }
  }
  delete req.session.awaitingPaymentOrder;
  delete req.session.pendingPaymentOrderId;
  setFlash(req, 'danger', 'Ödeme işlemi tamamlanamadı. Lütfen tekrar deneyin.');
  res.redirect('/checkout');
});

// Customer authentication
app.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/account');
  }
  const form = req.session.formData || {};
  delete req.session.formData;
  res.render('auth/register', { form });
});

app.post('/register', async (req, res) => {
  const { name, email, password, phone } = req.body;
  const trimmedName = name ? name.trim() : '';
  const emailNormalized = email ? email.trim().toLowerCase() : '';
  const phoneNormalized = phone ? phone.trim() : '';
  const formData = { name: trimmedName, email: emailNormalized, phone: phoneNormalized };
  req.session.formData = formData;

  if (!trimmedName || !emailNormalized || !password || !phoneNormalized) {
    setFlash(req, 'danger', 'Tüm alanlar zorunludur.');
    return res.redirect('/register');
  }

  const phoneDigits = phoneNormalized.replace(/\D/g, '');
  if (phoneDigits.length < 10) {
    setFlash(req, 'danger', 'Lütfen telefon numaranızı doğru formatta girin.');
    return res.redirect('/register');
  }

  const existing = db.prepare('SELECT id FROM customers WHERE email = ?').get(emailNormalized);
  if (existing) {
    setFlash(req, 'danger', 'Bu e-posta ile zaten kayıtlı bir hesap var.');
    return res.redirect('/register');
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const result = db
    .prepare('INSERT INTO customers (name, email, phone, password_hash) VALUES (?, ?, ?, ?)')
    .run(trimmedName, emailNormalized, phoneNormalized, passwordHash);

  req.session.user = { id: result.lastInsertRowid, name: trimmedName, email: emailNormalized, phone: phoneNormalized };
  delete req.session.formData;

  const siteSettings = res.locals.settings || {};
  const welcomeHtml = `
    <h1>Tea2Tea'ye hoş geldiniz!</h1>
    <p>Sayın ${trimmedName}, hesabınız başarıyla oluşturuldu.</p>
    <p>Artık siparişlerinizi daha kolay takip edebilir ve hızlıca ödeme yapabilirsiniz.</p>
  `;
  await sendEmail(emailNormalized, `${siteSettings.site_name || 'Tea2Tea'} Hesabınız`, welcomeHtml);

  setFlash(req, 'success', 'Hoş geldiniz!');
  res.redirect('/account');
});

app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/account');
  }
  const form = req.session.formData || {};
  delete req.session.formData;
  res.render('auth/login', { form });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const formData = { email: email || '' };
  req.session.formData = formData;

  if (!email || !password) {
    setFlash(req, 'danger', 'Lütfen e-posta ve şifrenizi girin.');
    return res.redirect('/login');
  }

  const emailNormalized = email.trim().toLowerCase();
  const user = db
    .prepare('SELECT id, name, email, phone, password_hash AS passwordHash FROM customers WHERE email = ?')
    .get(emailNormalized);

  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    setFlash(req, 'danger', 'E-posta veya şifre hatalı.');
    return res.redirect('/login');
  }

  req.session.user = { id: user.id, name: user.name, email: user.email, phone: user.phone || '' };
  delete req.session.formData;
  setFlash(req, 'success', 'Tekrar hoş geldiniz!');
  res.redirect('/account');
});

app.post('/logout', (req, res) => {
  delete req.session.user;
  setFlash(req, 'success', 'Çıkış yapıldı.');
  res.redirect('/');
});

app.post('/subscriptions', requireUser, (req, res) => {
  const existing = getActiveSubscription(req.session.user.id);
  if (existing && existing.status === 'active') {
    setFlash(req, 'info', 'Tea Lab aboneliğiniz zaten aktif.');
    return res.redirect('/account');
  }

  try {
    db.prepare(
      `INSERT INTO subscriptions (customer_id, plan, price, gram_amount, status)
       VALUES (?, ?, ?, ?, 'active')`,
    ).run(req.session.user.id, TEA_LAB_PLAN.code, TEA_LAB_PLAN.price, TEA_LAB_PLAN.grams);
    setFlash(req, 'success', 'Tea Lab aboneliğiniz aktif edildi. Her ay 100 g özel harman gönderilecek.');
  } catch (error) {
    console.error('Failed to create subscription', error);
    setFlash(req, 'danger', 'Abonelik oluşturulamadı. Lütfen daha sonra tekrar deneyin.');
  }

  res.redirect('/account');
});

app.post('/subscriptions/cancel', requireUser, (req, res) => {
  const subscription = getActiveSubscription(req.session.user.id);
  if (!subscription || subscription.status !== 'active') {
    setFlash(req, 'info', 'Aktif bir Tea Lab aboneliğiniz bulunmuyor.');
    return res.redirect('/account');
  }

  try {
    db.prepare('UPDATE subscriptions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(
      'cancelled',
      subscription.id,
    );
    setFlash(req, 'success', 'Tea Lab aboneliğiniz iptal edildi. İstediğiniz zaman tekrar katılabilirsiniz.');
  } catch (error) {
    console.error('Failed to cancel subscription', error);
    setFlash(req, 'danger', 'Abonelik iptal edilirken bir sorun oluştu.');
  }

  res.redirect('/account');
});

app.get('/account', requireUser, (req, res) => {
  const orders = db
    .prepare(
      `SELECT order_number AS orderNumber, total_amount AS totalAmount, paid_at AS paidAt, created_at AS createdAt
       FROM orders WHERE customer_id = ? AND status = 'paid' ORDER BY COALESCE(paid_at, created_at) DESC`,
    )
    .all(req.session.user.id);
  const blends = db
    .prepare(
      `SELECT id, name, total_grams AS totalGrams, is_shared AS isShared, created_at AS createdAt
       FROM blends WHERE user_id = ? ORDER BY created_at DESC`
    )
    .all(req.session.user.id);

  const subscription = getActiveSubscription(req.session.user.id);

  res.render('account/index', { orders, blends, subscription, teaLabPlan: TEA_LAB_PLAN });
});

app.get('/blends/create', requireUser, (req, res) => {
  const products = db
    .prepare('SELECT id, name, price, grams, image_url AS imageUrl FROM products WHERE is_active = 1 ORDER BY name ASC')
    .all();
  const form = req.session.formData || {};
  delete req.session.formData;
  res.render('blends/create', { products, form });
});

app.post('/blends', requireUser, (req, res) => {
  const { name, description, isShared } = req.body;
  const gramsInput = req.body.grams || {};
  const trimmedName = name?.trim();
  req.session.formData = { name: trimmedName, description, isShared, grams: gramsInput };

  if (!trimmedName) {
    setFlash(req, 'danger', 'Karışım adı zorunludur.');
    return res.redirect('/blends/create');
  }

  const entries = Object.entries(gramsInput)
    .map(([productId, value]) => ({ productId: Number(productId), grams: Number(value) || 0 }))
    .filter((entry) => entry.productId && entry.grams > 0);

  if (entries.length === 0) {
    setFlash(req, 'danger', 'En az bir ürüne gramaj vermelisiniz.');
    return res.redirect('/blends/create');
  }

  const totalGrams = entries.reduce((sum, entry) => sum + entry.grams, 0);
  const isSharedFlag = isShared ? 1 : 0;

  const insertBlend = db.prepare(
    'INSERT INTO blends (user_id, name, description, total_grams, is_shared) VALUES (?, ?, ?, ?, ?)',
  );
  const insertItem = db.prepare(
    'INSERT INTO blend_items (blend_id, product_id, grams) VALUES (?, ?, ?)',
  );

  const tx = db.transaction(() => {
    const result = insertBlend.run(req.session.user.id, trimmedName, description?.trim() || '', totalGrams, isSharedFlag);
    entries.forEach((entry) => insertItem.run(result.lastInsertRowid, entry.productId, entry.grams));
    return result.lastInsertRowid;
  });

  const blendId = tx();
  delete req.session.formData;
  setFlash(req, 'success', 'Karışım oluşturuldu.');
  res.redirect(`/blends/${blendId}`);
});

app.get('/blends/:id', (req, res) => {
  const blend = db
    .prepare(
      `SELECT b.id, b.user_id AS userId, b.name, b.description, b.total_grams AS totalGrams, b.is_shared AS isShared,
              b.created_at AS createdAt, c.name AS ownerName
       FROM blends b
       JOIN customers c ON c.id = b.user_id
       WHERE b.id = ?`
    )
    .get(req.params.id);

  if (!blend) {
    return res.status(404).render('shop/not-found', { message: 'Karışım bulunamadı.' });
  }

  const isOwner = req.session.user && req.session.user.id === blend.userId;
  if (!blend.isShared && !isOwner) {
    return res.status(403).render('shop/not-found', { message: 'Bu karışım yalnızca sahibi tarafından görüntülenebilir.' });
  }

  const items = db
    .prepare(
      `SELECT bi.product_id AS productId, bi.grams,
              p.name AS productName, p.price AS productPrice, p.grams AS productGrams
       FROM blend_items bi
       JOIN products p ON p.id = bi.product_id
       WHERE bi.blend_id = ?`
    )
    .all(blend.id);

  const totalPrice = calculateBlendPrice(items);

  const ratingStats = db
    .prepare(
      'SELECT IFNULL(AVG(rating),0) AS avgRating, COUNT(*) AS ratingCount FROM blend_comments WHERE blend_id = ?',
    )
    .get(blend.id);

  const comments = db
    .prepare(
      `SELECT bc.id, bc.rating, bc.comment, bc.created_at AS createdAt, cust.name AS author
       FROM blend_comments bc
       JOIN customers cust ON cust.id = bc.user_id
       WHERE bc.blend_id = ?
       ORDER BY bc.created_at DESC`
    )
    .all(blend.id);

  res.render('blends/detail', {
    blend,
    items,
    totalPrice,
    isOwner,
    ratingStats,
    comments,
  });
});

app.post('/blends/:id/cart', requireUser, (req, res) => {
  const blend = db
    .prepare('SELECT id, user_id AS userId, name, total_grams AS totalGrams, is_shared AS isShared FROM blends WHERE id = ?')
    .get(req.params.id);

  if (!blend) {
    setFlash(req, 'danger', 'Karışım bulunamadı.');
    return res.redirect('/blends/create');
  }

  if (!blend.isShared && req.session.user.id !== blend.userId) {
    setFlash(req, 'danger', 'Bu karışım sipariş verilemez.');
    return res.redirect('/blends/create');
  }

  const components = db
    .prepare(
      `SELECT bi.product_id AS productId, bi.grams,
              p.name AS productName, p.price AS productPrice, p.grams AS productGrams
       FROM blend_items bi
       JOIN products p ON p.id = bi.product_id
       WHERE bi.blend_id = ?`
    )
    .all(blend.id);

  if (!components.length) {
    setFlash(req, 'danger', 'Karışım ürün içermiyor.');
    return res.redirect(`/blends/${blend.id}`);
  }

  const price = calculateBlendPrice(components);
  const cart = ensureCart(req);
  const key = `blend-${blend.id}-${Date.now()}`;
  cart.items[key] = {
    key,
    type: 'blend',
    blendId: blend.id,
    name: `${blend.name} Karışımı`,
    price: parseFloat(price.toFixed(2)),
    quantity: 1,
    components,
  };
  recalcCart(cart);
  setFlash(req, 'success', 'Karışım sepete eklendi.');
  res.redirect('/cart');
});

app.get('/community', (req, res) => {
  const rawBlends = db
    .prepare(
      `SELECT b.id, b.name, b.description, b.total_grams AS totalGrams, b.created_at AS createdAt,
              c.name AS ownerName,
              IFNULL(avgData.avgRating, 0) AS avgRating,
              IFNULL(avgData.ratingCount, 0) AS ratingCount
       FROM blends b
       JOIN customers c ON c.id = b.user_id
       LEFT JOIN (
         SELECT blend_id, AVG(rating) AS avgRating, COUNT(*) AS ratingCount
         FROM blend_comments
         GROUP BY blend_id
       ) AS avgData ON avgData.blend_id = b.id
       WHERE b.is_shared = 1
       ORDER BY b.created_at DESC`
    )
    .all();

  const blends = rawBlends.map((blend) => {
    const components = db
      .prepare(
        `SELECT bi.product_id AS productId, bi.grams,
                p.name AS productName, p.price AS productPrice, p.grams AS productGrams,
                p.image_url AS productImageUrl
         FROM blend_items bi
         JOIN products p ON p.id = bi.product_id
         WHERE bi.blend_id = ?`
      )
      .all(blend.id);
    const totalPrice = calculateBlendPrice(components);
    const previewImage = components.find((component) => component.productImageUrl)?.productImageUrl || null;
    const previewProducts = components.slice(0, 3).map((component) => component.productName);
    const componentSummary = components
      .map((component) => `${component.productName} (${component.grams} g)`)
      .join(' • ');
    return {
      ...blend,
      totalPrice,
      components,
      previewImage,
      previewProducts,
      componentSummary,
    };
  });

  res.render('blends/community', { blends });
});

app.get('/tea-lab', (req, res) => {
  const subscription = req.session.user ? getActiveSubscription(req.session.user.id) : null;
  res.render('shop/tea-lab', { subscription, teaLabPlan: TEA_LAB_PLAN });
});

app.post('/blends/:id/comments', requireUser, (req, res) => {
  const { rating, comment } = req.body;
  const blend = db
    .prepare('SELECT id, is_shared, user_id AS userId FROM blends WHERE id = ?')
    .get(req.params.id);

  if (!blend) {
    setFlash(req, 'danger', 'Karışım bulunamadı.');
    return res.redirect('/community');
  }

  if (!blend.is_shared && blend.userId !== req.session.user.id) {
    setFlash(req, 'danger', 'Bu karışım için yorum yapılamaz.');
    return res.redirect('/community');
  }

  const ratingValue = Number(rating);
  if (!ratingValue || ratingValue < 1 || ratingValue > 5) {
    setFlash(req, 'danger', 'Lütfen 1 ile 5 arasında bir puan seçin.');
    return res.redirect(`/blends/${blend.id}`);
  }

  db.prepare('INSERT INTO blend_comments (blend_id, user_id, rating, comment) VALUES (?, ?, ?, ?)').run(
    blend.id,
    req.session.user.id,
    ratingValue,
    comment?.trim() || null,
  );

  setFlash(req, 'success', 'Yorumunuz kaydedildi.');
  res.redirect(`/blends/${blend.id}`);
});

// Admin authentication
app.get('/admin/login', (req, res) => {
  if (req.session.isAdmin) {
    return res.redirect('/admin');
  }
  res.render('admin/login');
});

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  const admin = db
    .prepare('SELECT id, username, password_hash AS passwordHash FROM admin_users WHERE username = ?')
    .get(username);

  if (!admin) {
    setFlash(req, 'danger', 'Kullanıcı adı ya da şifre hatalı.');
    return res.redirect('/admin/login');
  }

  const valid = bcrypt.compareSync(password, admin.passwordHash);
  if (!valid) {
    setFlash(req, 'danger', 'Kullanıcı adı ya da şifre hatalı.');
    return res.redirect('/admin/login');
  }

  req.session.isAdmin = true;
  req.session.adminUser = { id: admin.id, username: admin.username };
  setFlash(req, 'success', 'Hoş geldiniz!');
  res.redirect('/admin');
});

app.post('/admin/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/admin/login');
  });
});

// All routes below require admin
app.use('/admin', requireAdmin);

app.get('/admin', (req, res) => {
  const totalProducts = db.prepare('SELECT COUNT(*) AS count FROM products').get().count;
  const totalOrders = db.prepare("SELECT COUNT(*) AS count FROM orders WHERE status = 'paid'").get().count;
  const totalRevenue = db.prepare("SELECT IFNULL(SUM(total_amount), 0) AS total FROM orders WHERE status = 'paid'").get()
    .total;
  const recentOrders = db
    .prepare(
      `SELECT id, order_number AS orderNumber, customer_name AS customerName, total_amount AS totalAmount,
              created_at AS createdAt, status
       FROM orders ORDER BY created_at DESC LIMIT 5`,
    )
    .all();

  res.render('admin/dashboard', {
    stats: {
      totalProducts,
      totalOrders,
      totalRevenue,
    },
    recentOrders,
  });
});

// Product management
app.get('/admin/products', (req, res) => {
  const products = db
    .prepare(
      `SELECT id, name, slug, price, grams, stock, is_active AS isActive, created_at AS createdAt
       FROM products ORDER BY created_at DESC`,
    )
    .all();
  res.render('admin/products/list', { products });
});

app.get('/admin/products/new', (req, res) => {
  res.render('admin/products/form', { product: null });
});

app.post('/admin/products', upload.single('imageFile'), (req, res) => {
  const { name, slug, price, description, grams, imageUrl, stock, isActive } = req.body;

  if (!name || !price) {
    setFlash(req, 'danger', 'İsim ve fiyat zorunlu alanlardır.');
    return res.redirect('/admin/products/new');
  }

  const imageUrlInput = imageUrl?.trim();
  const uploadedPath = req.file ? `/uploads/${req.file.filename}` : '';
  const finalImageUrl = imageUrlInput || uploadedPath;

  const productData = {
    name: name.trim(),
    slug: slug ? slugify(slug) : slugify(name),
    description: description?.trim() || '',
    price: parseFloat(price),
    image_url: finalImageUrl,
    grams: parseInt(grams, 10) || 0,
    stock: parseInt(stock, 10) || 0,
    is_active: isActive ? 1 : 0,
  };

  try {
    db.prepare(
      `INSERT INTO products (name, slug, description, price, grams, image_url, stock, is_active)
       VALUES (@name, @slug, @description, @price, @grams, @image_url, @stock, @is_active)`,
    ).run(productData);
    setFlash(req, 'success', 'Ürün eklendi.');
    res.redirect('/admin/products');
  } catch (err) {
    console.error('Failed to create product', err);
    const message = err.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 'Bu ürün adresi (slug) zaten mevcut.' : 'Ürün eklenirken bir hata oluştu.';
    setFlash(req, 'danger', message);
    res.redirect('/admin/products/new');
  }
});

app.get('/admin/products/:id/edit', (req, res) => {
  const product = db
    .prepare(
      `SELECT id, name, slug, description, price, grams, image_url AS imageUrl, stock, is_active AS isActive
       FROM products WHERE id = ?`,
    )
    .get(req.params.id);

  if (!product) {
    setFlash(req, 'danger', 'Ürün bulunamadı.');
    return res.redirect('/admin/products');
  }

  res.render('admin/products/form', { product });
});

app.put('/admin/products/:id', upload.single('imageFile'), (req, res) => {
  const { name, slug, price, description, grams, imageUrl, stock, isActive } = req.body;
  const product = db.prepare('SELECT id, image_url FROM products WHERE id = ?').get(req.params.id);

  if (!product) {
    setFlash(req, 'danger', 'Ürün bulunamadı.');
    return res.redirect('/admin/products');
  }

  const imageUrlInput = imageUrl?.trim();
  let finalImageUrl = imageUrlInput || product.image_url;
  if (req.file) {
    finalImageUrl = `/uploads/${req.file.filename}`;
  }

  const payload = {
    name: name.trim(),
    slug: slug ? slugify(slug) : slugify(name),
    description: description?.trim() || '',
    price: parseFloat(price),
    image_url: finalImageUrl,
    grams: parseInt(grams, 10) || 0,
    stock: parseInt(stock, 10) || 0,
    is_active: isActive ? 1 : 0,
    id: product.id,
  };

  try {
    db.prepare(
      `UPDATE products SET
        name = @name,
        slug = @slug,
        description = @description,
        price = @price,
        grams = @grams,
        image_url = @image_url,
        stock = @stock,
        is_active = @is_active
      WHERE id = @id`,
    ).run(payload);
    setFlash(req, 'success', 'Ürün güncellendi.');
  } catch (err) {
    console.error('Failed to update product', err);
    const message =
      err.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 'Bu ürün adresi (slug) zaten mevcut.' : 'Ürün güncellenirken hata oluştu.';
    setFlash(req, 'danger', message);
  }
  res.redirect('/admin/products');
});

app.delete('/admin/products/:id', (req, res) => {
  try {
    db.prepare('DELETE FROM products WHERE id = ?').run(req.params.id);
    setFlash(req, 'success', 'Ürün silindi.');
  } catch (err) {
    console.error('Failed to delete product', err);
    setFlash(req, 'danger', 'Ürün silinirken hata oluştu.');
  }
  res.redirect('/admin/products');
});

// Orders
app.get('/admin/orders', (req, res) => {
  const orders = db
    .prepare(
      `SELECT id, order_number AS orderNumber, customer_name AS customerName, total_amount AS totalAmount,
              created_at AS createdAt, status
       FROM orders ORDER BY created_at DESC`,
    )
    .all();
  res.render('admin/orders/list', { orders });
});

app.get('/admin/orders/:id', (req, res) => {
  const order = db
    .prepare(
      `SELECT id, order_number AS orderNumber, customer_name AS customerName, customer_email AS customerEmail,
              customer_phone AS customerPhone, customer_address AS customerAddress, customer_city AS customerCity,
              customer_notes AS customerNotes, total_amount AS totalAmount, created_at AS createdAt, status,
              paid_at AS paidAt, payment_provider AS paymentProvider, payment_reference AS paymentReference
       FROM orders WHERE id = ?`,
    )
    .get(req.params.id);

  if (!order) {
    setFlash(req, 'danger', 'Sipariş bulunamadı.');
    return res.redirect('/admin/orders');
  }

  const items = db
    .prepare(
      `SELECT product_name AS productName, unit_price AS unitPrice, quantity
       FROM order_items WHERE order_id = ?`,
    )
    .all(order.id);

  res.render('admin/orders/detail', { order, items });
});

// Settings
app.get('/admin/settings', (req, res) => {
  const settings = getAllSettings();
  res.render('admin/settings', { settings });
});

app.post('/admin/settings', upload.single('bannerFile'), (req, res) => {
  const updates = {};
  Object.entries(req.body || {}).forEach(([key, value]) => {
    if (typeof value === 'string') {
      updates[key] = value.trim();
    }
  });

  if (req.file) {
    updates.store_banner = `/uploads/${req.file.filename}`;
  }

  try {
    Object.entries(updates).forEach(([key, value]) => {
      setSetting(key, value);
    });
    setFlash(req, 'success', 'Ayarlar güncellendi.');
  } catch (err) {
    console.error('Failed to update settings', err);
    setFlash(req, 'danger', 'Ayarlar güncellenemedi.');
  }

  res.redirect('/admin/settings');
});

// Admin password change
app.post('/admin/settings/change-password', (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    setFlash(req, 'danger', 'Yeni şifre en az 6 karakter olmalıdır.');
    return res.redirect('/admin/settings');
  }

  const adminSession = req.session.adminUser;
  if (!adminSession) {
    setFlash(req, 'danger', 'Oturum bulunamadı.');
    return res.redirect('/admin/settings');
  }

  const admin = db
    .prepare('SELECT id, password_hash AS passwordHash FROM admin_users WHERE id = ?')
    .get(adminSession.id);

  if (!admin) {
    setFlash(req, 'danger', 'Yönetici bulunamadı.');
    return res.redirect('/admin/settings');
  }

  if (!bcrypt.compareSync(currentPassword, admin.passwordHash)) {
    setFlash(req, 'danger', 'Mevcut şifre hatalı.');
    return res.redirect('/admin/settings');
  }

  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE admin_users SET password_hash = ? WHERE id = ?').run(hash, admin.id);
  setFlash(req, 'success', 'Şifre güncellendi.');
  res.redirect('/admin/settings');
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('shop/not-found', { message: 'Aradığınız sayfa bulunamadı.' });
});

app.listen(PORT, () => {
  console.log(`Tea2Tea sunucusu http://localhost:${PORT} adresinde çalışıyor`);
});
