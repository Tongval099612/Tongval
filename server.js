// server.js
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');

const SECRET = 'replace_this_with_a_strong_secret_!@#'; // เปลี่ยนเป็นค่าที่แข็งแรงก่อนนำขึ้นโปรดักชั่น
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'app.db');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- Initialize DB ---
const db = new sqlite3.Database(DB_FILE);

function runAsync(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function allAsync(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function getAsync(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

async function initDB() {
  // tables: admins, customers, transactions, settings
  await runAsync(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    display_name TEXT
  )`);

  await runAsync(`CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    phone TEXT,
    note TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  await runAsync(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER,
    type TEXT, -- deposit or withdraw
    amount REAL,
    status TEXT, -- pending/approved/rejected
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(customer_id) REFERENCES customers(id)
  )`);

  await runAsync(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  )`);

  // default commission setting (%)
  const existing = await getAsync('SELECT value FROM settings WHERE key = ?', ['commission_percent']);
  if (!existing) {
    await runAsync('INSERT INTO settings(key, value) VALUES(?,?)', ['commission_percent', '2.5']); // ค่าเริ่มต้น 2.5%
  }

  // default admin user (username: admin) ถ้าไม่มีให้สร้าง (รหัส: Admin@123)
  const admin = await getAsync('SELECT id FROM admins WHERE username = ?', ['admin']);
  if (!admin) {
    const hash = await bcrypt.hash('Admin@123', 10);
    await runAsync('INSERT INTO admins(username, password_hash, display_name) VALUES(?,?,?)', ['admin', hash, 'Administrator']);
    console.log('Default admin created: username=admin password=Admin@123 (เปลี่ยนรหัสทันที)');
  }
}

initDB().catch(err => {
  console.error('DB init error', err);
  process.exit(1);
});

// --- Helper: auth middleware ---
function authMiddleware(req, res, next) {
  const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const payload = jwt.verify(token, SECRET);
    req.admin = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Auth endpoints ---
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const row = await getAsync('SELECT * FROM admins WHERE username = ?', [username]);
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: row.id, username: row.username, display_name: row.display_name }, SECRET, { expiresIn: '8h' });
    res.json({ token, admin: { id: row.id, username: row.username, display_name: row.display_name } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

app.get('/api/admin/me', authMiddleware, async (req, res) => {
  res.json({ admin: req.admin });
});

// --- Customers CRUD ---
app.get('/api/customers', authMiddleware, async (req, res) => {
  const rows = await allAsync('SELECT * FROM customers ORDER BY id DESC');
  res.json({ customers: rows });
});

app.post('/api/customers', authMiddleware, async (req, res) => {
  const { name, email, phone, note } = req.body;
  try {
    const r = await runAsync('INSERT INTO customers(name,email,phone,note) VALUES(?,?,?,?)', [name,email,phone,note]);
    res.json({ id: r.lastID });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.put('/api/customers/:id', authMiddleware, async (req, res) => {
  const id = req.params.id;
  const { name, email, phone, note } = req.body;
  try {
    await runAsync('UPDATE customers SET name=?, email=?, phone=?, note=? WHERE id=?', [name,email,phone,note,id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.delete('/api/customers/:id', authMiddleware, async (req, res) => {
  const id = req.params.id;
  try {
    await runAsync('DELETE FROM customers WHERE id=?', [id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- Transactions (ฝาก/ถอน) ---
app.get('/api/transactions', authMiddleware, async (req, res) => {
  const rows = await allAsync(`SELECT t.*, c.name as customer_name, c.email as customer_email
    FROM transactions t
    LEFT JOIN customers c ON t.customer_id = c.id
    ORDER BY t.created_at DESC`);
  res.json({ transactions: rows });
});

app.post('/api/transactions', authMiddleware, async (req, res) => {
  const { customer_id, type, amount, status } = req.body;
  if (!customer_id || !type || !amount) return res.status(400).json({ error: 'customer_id, type, amount required' });
  try {
    const r = await runAsync('INSERT INTO transactions(customer_id,type,amount,status) VALUES(?,?,?,?)', [customer_id, type, amount, status || 'pending']);
    res.json({ id: r.lastID });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.put('/api/transactions/:id', authMiddleware, async (req, res) => {
  const id = req.params.id;
  const { status } = req.body;
  try {
    await runAsync('UPDATE transactions SET status=? WHERE id=?', [status, id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.delete('/api/transactions/:id', authMiddleware, async (req, res) => {
  const id = req.params.id;
  try {
    await runAsync('DELETE FROM transactions WHERE id=?', [id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- Settings (เช่น ตั้ง%ค่าคอม) ---
app.get('/api/settings', authMiddleware, async (req, res) => {
  const rows = await allAsync('SELECT key, value FROM settings');
  const settings = {};
  rows.forEach(r => settings[r.key] = r.value);
  res.json({ settings });
});

app.post('/api/settings', authMiddleware, async (req, res) => {
  const entries = req.body; // expected object { key: value, ... }
  try {
    const keys = Object.keys(entries || {});
    for (const k of keys) {
      const v = String(entries[k]);
      const exist = await getAsync('SELECT key FROM settings WHERE key=?', [k]);
      if (exist) {
        await runAsync('UPDATE settings SET value=? WHERE key=?', [v, k]);
      } else {
        await runAsync('INSERT INTO settings(key, value) VALUES(?,?)', [k, v]);
      }
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- Commission summary endpoint ---
app.get('/api/commission-summary', authMiddleware, async (req, res) => {
  // commission percent from settings
  const s = await getAsync('SELECT value FROM settings WHERE key = ?', ['commission_percent']);
  const percent = s ? parseFloat(s.value) : 0;

  // compute totals
  const deposits = await allAsync("SELECT SUM(amount) as total FROM transactions WHERE type='deposit' AND status='approved'");
  const withdraws = await allAsync("SELECT SUM(amount) as total FROM transactions WHERE type='withdraw' AND status='approved'");

  const total_deposit = deposits && deposits[0].total ? parseFloat(deposits[0].total) : 0;
  const total_withdraw = withdraws && withdraws[0].total ? parseFloat(withdraws[0].total) : 0;

  // commission calc example: commission on deposits = percent% of deposits
  const commission_on_deposits = total_deposit * percent / 100;

  res.json({
    percent,
    total_deposit,
    total_withdraw,
    commission_on_deposits,
    summary_date: new Date().toISOString()
  });
});

// --- Fallback to admin UI ---
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
