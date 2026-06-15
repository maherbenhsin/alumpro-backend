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

// ═══════════════════════ HEALTH CHECK ═══════════════════════
app.get('/api/health', (req, res) => {
  res.json({ status: 'API Running' });
});

// ═══════════════════════ INIT ADMIN ═══════════════════════
app.post('/api/init-admin', async (req, res) => {
  try {
    const check = await pool.query('SELECT id FROM users WHERE email = $1', ['admin@alumpro.tn']);
    if (check.rows.length > 0) {
      return res.status(400).json({ error: 'Admin existe déjà' });
    }

    const hashedPass = await hashPassword('admin123');
    const result = await pool.query(
      'INSERT INTO users (name, email, password, phone, company, role, status) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name, email, role',
      ['Admin AlumPro', 'admin@alumpro.tn', hashedPass, '+216 71 123 456', 'AlumPro', 'admin', 'approved']
    );

    res.status(201).json({
      message: 'Admin créé avec succès',
      admin: result.rows[0],
      credentials: { email: 'admin@alumpro.tn', password: 'admin123' }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════ AUTH ═══════════════════════
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
    if (exists.rows.length > 0) return res.status(400).json({ error: 'Email déjà utilisé' });

    const hashedPass = await hashPassword(password);
    const result = await pool.query(
      'INSERT INTO users (name, email, password, phone, company, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, role',
      [name, email, hashedPass, phone, company, 'pending']
    );

    res.status(201).json({ message: 'Inscription réussie - En attente d\'approbation', user: result.rows[0] });
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
    if (user.status === 'pending') return res.status(401).json({ error: 'Compte en attente d\'approbation' });
    if (user.status === 'rejected') return res.status(401).json({ error: 'Inscription refusée' });

    const validPass = await comparePassword(password, user.password);
    if (!validPass) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

    const token = generateToken(user.id, user.role);
    res.json({
      message: 'Connexion réussie',
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role, status: user.status }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════ PRODUCTS ═══════════════════════
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

// ═══════════════════════ ORDERS ═══════════════════════
app.post('/api/orders', verifyToken, async (req, res) => {
  try {
    const { items, total, address } = req.body;
    const orderNumber = 'CMD' + Date.now();
    const result = await pool.query(
      'INSERT INTO orders (order_number, user_id, items, total, shipping_address) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [orderNumber, req.user.userId, JSON.stringify(items), total, address]
    );
    await pool.query('INSERT INTO notifications (user_id, message) VALUES ($1, $2)', [req.user.userId, `Commande ${orderNumber} créée`]);
    res.status(201).json({ message: 'Commande créée', order: result.rows[0] });
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

// ═══════════════════════ ADMIN ═══════════════════════
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
    if (result.rows.length === 0) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    await pool.query('INSERT INTO notifications (user_id, message) VALUES ($1, $2)', [req.params.id, 'Votre compte a été approuvé']);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/admin/users/:id/reject', verifyToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query("UPDATE users SET status = 'rejected', updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *", [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    await pool.query('INSERT INTO notifications (user_id, message) VALUES ($1, $2)', [req.params.id, 'Votre demande a été refusée']);
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

app.patch('/api/admin/products/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { price, stock } = req.body;
    const result = await pool.query(
      'UPDATE products SET price = COALESCE($1, price), stock = COALESCE($2, stock), updated_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING *',
      [price, stock, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Produit non trouvé' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════ START ═══════════════════════
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`API démarrée sur le port ${PORT}`);
});