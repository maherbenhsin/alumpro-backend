const express = require('express');
const pg = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.on('error', (err) => {
  console.error('Erreur pool:', err);
});

const hashPassword = async (pass) => await bcrypt.hash(pass, 10);
const comparePassword = async (pass, hash) => await bcrypt.compare(pass, hash);

const generateToken = (userId, role) => {
  return jwt.sign({ userId, role }, process.env.JWT_SECRET, { expiresIn: '30d' });
};

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token manquant' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token invalide' });
  }
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin requis' });
  next();
};

// ============ HEALTH CHECK ============
app.get('/api/health', (req, res) => {
  res.json({ status: 'API Running' });
});

// ============ INIT DATABASE (PROTEGE) ============
app.post('/api/init-db', async (req, res) => {
  if (req.headers['x-init-secret'] !== process.env.INIT_SECRET) {
    return res.status(403).json({ error: 'Acces refuse' });
  }
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        phone VARCHAR(20),
        company VARCHAR(255),
        address TEXT,
        role VARCHAR(50) DEFAULT 'client',
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        reference VARCHAR(100) UNIQUE NOT NULL,
        category VARCHAR(100),
        price DECIMAL(10,2) NOT NULL,
        unit VARCHAR(50),
        icon VARCHAR(10),
        stock INTEGER DEFAULT 0,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        order_number VARCHAR(100) UNIQUE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        total DECIMAL(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        payment_status VARCHAR(50) DEFAULT 'unpaid',
        shipping_address TEXT,
        items JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        message TEXT NOT NULL,
        read BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id);
    `);

    const check = await pool.query('SELECT COUNT(*) FROM products');
    if (parseInt(check.rows[0].count) === 0) {
      await pool.query(`
        INSERT INTO products (name, reference, category, price, unit, icon, stock, description) VALUES
        ('Profile Carre 40x40', 'ALU-C4040', 'structure', 18.5, 'ml', 'BLK', 50, 'Profile carre standard'),
        ('Profile Carre 60x60', 'ALU-C6060', 'structure', 27.0, 'ml', 'BLK', 35, 'Profile carre renforce'),
        ('Profile Plat 30x3', 'ALU-P3003', 'structure', 9.8, 'ml', 'BAR', 120, 'Profile plat leger'),
        ('Profile Decoratif', 'ALU-DA-45', 'deco', 14.0, 'ml', 'DEC', 45, 'Angle decoratif'),
        ('Kit Connecteur 90', 'ACC-KIT90', 'accessoire', 12.5, 'lot', 'KIT', 78, 'Lot de 4 connecteurs'),
        ('Equerre Aluminium', 'ACC-EQ50', 'accessoire', 4.2, 'unite', 'EQR', 200, 'Equerre standard');
      `);
    }

    res.json({ message: 'Base de donnees initialisee avec succes' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ INIT ADMIN (PROTEGE) ============
app.post('/api/init-admin', async (req, res) => {
  if (req.headers['x-init-secret'] !== process.env.INIT_SECRET) {
    return res.status(403).json({ error: 'Acces refuse' });
  }
  try {
    const check = await pool.query('SELECT id FROM users WHERE email = $1', ['admin@alumpro.tn']);
    if (check.rows.length > 0) {
      return res.status(400).json({ error: 'Admin existe deja' });
    }

    const hashedPass = await hashPassword('admin123');
    const result = await pool.query(
      'INSERT INTO users (name, email, password, phone, company, role, status) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name, email, role',
      ['Admin AlumPro', 'admin@alumpro.tn', hashedPass, '+216 71 123 456', 'AlumPro', 'admin', 'approved']
    );

    res.status(201).json({
      message: 'Admin cree avec succes',
      admin: result.rows[0],
      credentials: { email: 'admin@alumpro.tn', password: 'admin123' }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ AUTH ============
app.post('/api/auth/register', [
  body('name').notEmpty(),
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  body('phone').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { name, email, password, phone, company } = req.body;
    const exists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (exists.rows.length > 0) return res.status(400).json({ error: 'Email deja utilise' });

    const hashedPass = await hashPassword(password);
    const result = await pool.query(
      'INSERT INTO users (name, email, password, phone, company, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, role',
      [name, email, hashedPass, phone, company, 'pending']
    );

    res.status(201).json({ message: "Inscription reussie - En attente d'approbation", user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', [
  body('email').isEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

    const user = result.rows[0];
    if (user.status === 'pending') return res.status(401).json({ error: "Compte en attente d'approbation" });
    if (user.status === 'rejected') return res.status(401).json({ error: 'Inscription refusee' });

    const validPass = await comparePassword(password, user.password);
    if (!validPass) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

    const token = generateToken(user.id, user.role);
    res.json({
      message: 'Connexion reussie',
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role, status: user.status }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ PRODUCTS ============
app.get('/api/products', async (req, res) => {
  try {
    const { category, search, sort } = req.query;
    let query = 'SELECT * FROM products WHERE 1=1';
    const params = [];

    if (category && category !== 'all') {
      params.push(category);
      query += ` AND category = $${params.length}`;
    }
    if (search) {
      params.push(`%${search}%`);
      query += ` AND (name ILIKE $${params.length} OR reference ILIKE $${params.length})`;
    }
    if (sort === 'price-asc') query += ' ORDER BY price ASC';
    else if (sort === 'price-desc') query += ' ORDER BY price DESC';
    else if (sort === 'stock-desc') query += ' ORDER BY stock DESC';
    else query += ' ORDER BY name ASC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ ORDERS ============
app.post('/api/orders', verifyToken, async (req, res) => {
  try {
    const { items, total, address } = req.body;
    const orderNumber = 'CMD' + Date.now();
    const result = await pool.query(
      'INSERT INTO orders (order_number, user_id, items, total, shipping_address) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [orderNumber, req.user.userId, JSON.stringify(items), total, address]
    );
    await pool.query('INSERT INTO notifications (user_id, message) VALUES ($1, $2)', [req.user.userId, `Commande ${orderNumber} creee`]);
    res.status(201).json({ message: 'Commande creee', order: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/orders', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC', [req.user.userId]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ ADMIN ============
app.get('/api/admin/users', verifyToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, name, email, phone, company, status, created_at FROM users WHERE role = 'client'");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/admin/users/:id/approve', verifyToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query("UPDATE users SET status = 'approved', updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *", [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Utilisateur non trouve' });
    await pool.query('INSERT INTO notifications (user_id, message) VALUES ($1, $2)', [req.params.id, 'Votre compte a ete approuve']);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/admin/users/:id/reject', verifyToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query("UPDATE users SET status = 'rejected', updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *", [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Utilisateur non trouve' });
    await pool.query('INSERT INTO notifications (user_id, message) VALUES ($1, $2)', [req.params.id, 'Votre demande a ete refusee']);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/orders', verifyToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT o.*, u.name as user_name, u.email as user_email
      FROM orders o JOIN users u ON o.user_id = u.id
      ORDER BY o.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/admin/orders/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { status, payment_status } = req.body;
    const result = await pool.query(
      'UPDATE orders SET status = COALESCE($1, status), payment_status = COALESCE($2, payment_status), updated_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING *',
      [status, payment_status, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Commande non trouvee' });

    const order = result.rows[0];
    if (status) {
      await pool.query('INSERT INTO notifications (user_id, message) VALUES ($1, $2)', [order.user_id, `Commande ${order.order_number} - Statut: ${status}`]);
    }
    res.json(order);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/products', verifyToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products ORDER BY name ASC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/admin/products/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { price, stock } = req.body;
    const result = await pool.query(
      'UPDATE products SET price = COALESCE($1, price), stock = COALESCE($2, stock), updated_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING *',
      [price, stock, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Produit non trouve' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ START ============
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`API demarree sur le port ${PORT}`);
});