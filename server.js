// ============================================
// СИЗ: Учёт и движение — Сервер (всё в одном файле)
// Node.js + Express + PostgreSQL
// ============================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'siz-secret-key-change-me';

// ============ DATABASE ============

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
});
pool.on('error', (err) => console.error('DB pool error', err));

const db = async (text, params) => {
  const res = await pool.query(text, params);
  return res;
};

// ============ MIDDLEWARE ============

app.use(cors({ origin: process.env.CORS_ORIGIN || '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// JWT Auth
const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Требуется авторизация' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await db(
      `SELECT u.*, r.name as role_name, r.level as role_level, 
              r.general_permissions, r.field_permissions, r.display_name as role_display_name
       FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id = $1 AND u.is_active = true`,
      [decoded.userId]
    );
    if (result.rows.length === 0) return res.status(401).json({ error: 'Пользователь не найден' });
    req.user = result.rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: err.name === 'TokenExpiredError' ? 'Срок токена истёк' : 'Невалидный токен' });
  }
};

// Permission check
const perm = (p) => (req, res, next) => {
  if (!req.user.general_permissions?.[p]) return res.status(403).json({ error: `Нет права: ${p}` });
  next();
};

// Hierarchy check
const levelCheck = (levels) => (req, res, next) => {
  if (req.user.role_level === 'ia' || levels.includes(req.user.role_level)) return next();
  return res.status(403).json({ error: 'Недостаточно прав' });
};

// Token generation
const genToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: '24h' });

// Audit logging
const audit = async (userId, table, recordId, action, changes, ip) => {
  try {
    await db(`INSERT INTO audit_log (user_id, table_name, record_id, action, changes, ip_address) VALUES ($1,$2,$3,$4,$5,$6)`,
      [userId, table, recordId, action, JSON.stringify(changes || {}), ip]);
  } catch (e) { console.error('Audit error:', e.message); }
};

// ============ FLEX CRUD ============

class FlexCRUD {
  constructor(t) { this.t = t; }
  async getById(id) { const r = await db(`SELECT * FROM ${this.t} WHERE id = $1`, [id]); return r.rows[0] || null; }
  async create(data, uid, ip) {
    const { extra = {}, ...fields } = data;
    const keys = [...Object.keys(fields), 'extra'];
    const vals = [...Object.values(fields), JSON.stringify(extra)];
    const ph = vals.map((_, i) => `$${i + 1}`);
    const r = await db(`INSERT INTO ${this.t} (${keys.join(',')}) VALUES (${ph.join(',')}) RETURNING *`, vals);
    if (uid) await audit(uid, this.t, r.rows[0].id, 'create', data, ip);
    return r.rows[0];
  }
  async update(id, data, uid, ip) {
    const cur = await this.getById(id);
    if (!cur) throw new Error('Запись не найдена');
    const { extra, ...fields } = data;
    const sets = []; const vals = []; let i = 1;
    for (const [k, v] of Object.entries(fields)) { sets.push(`${k}=$${i}`); vals.push(v); i++; }
    if (extra && Object.keys(extra).length) { sets.push(`extra=extra||$${i}`); vals.push(JSON.stringify(extra)); i++; }
    if (!sets.length) throw new Error('Нет данных');
    vals.push(id);
    const r = await db(`UPDATE ${this.t} SET ${sets.join(',')} WHERE id=$${i} RETURNING *`, vals);
    if (uid) {
      const ch = {};
      for (const [k, v] of Object.entries(data)) { if (JSON.stringify(cur[k]) !== JSON.stringify(v)) ch[k] = { old: cur[k], new: v }; }
      await audit(uid, this.t, id, 'update', ch, ip);
    }
    return r.rows[0];
  }
  async softDelete(id, uid, ip) {
    const r = await db(`UPDATE ${this.t} SET is_active=false WHERE id=$1 RETURNING *`, [id]);
    if (uid && r.rows[0]) await audit(uid, this.t, id, 'delete', {}, ip);
    return r.rows[0];
  }
}

const catCRUD = new FlexCRUD('siz_categories');
const itemCRUD = new FlexCRUD('siz_items');
const posCRUD = new FlexCRUD('positions');
const empCRUD = new FlexCRUD('employees');
const orgCRUD = new FlexCRUD('organizations');
const entCRUD = new FlexCRUD('enterprises');
const resCRUD = new FlexCRUD('res_units');
const spbipkCRUD = new FlexCRUD('spbipk');
const deptCRUD = new FlexCRUD('departments');

// ============ ROUTES: AUTH ============

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Логин и пароль обязательны' });
    const result = await db(
      `SELECT u.*, r.name as role_name, r.level as role_level, r.display_name as role_display_name, r.general_permissions
       FROM users u JOIN roles r ON u.role_id = r.id WHERE u.username = $1 AND u.is_active = true`, [username]);
    if (!result.rows.length) return res.status(401).json({ error: 'Неверный логин или пароль' });
    const user = result.rows[0];
    if (!(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Неверный логин или пароль' });
    await db('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    res.json({
      token: genToken(user.id),
      user: { id: user.id, username: user.username, full_name: user.full_name, email: user.email,
        role_name: user.role_name, role_display_name: user.role_display_name, role_level: user.role_level,
        general_permissions: user.general_permissions, organization_id: user.organization_id,
        enterprise_id: user.enterprise_id, res_unit_id: user.res_unit_id }
    });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/auth/register', auth, async (req, res) => {
  try {
    if (req.user.role_level !== 'ia' || !req.user.general_permissions?.can_create)
      return res.status(403).json({ error: 'Недостаточно прав' });
    const { username, password, full_name, email, phone, role_id, organization_id, enterprise_id, res_unit_id } = req.body;
    if (!username || !password || !full_name || !role_id)
      return res.status(400).json({ error: 'username, password, full_name, role_id обязательны' });
    const ex = await db('SELECT id FROM users WHERE username=$1', [username]);
    if (ex.rows.length) return res.status(400).json({ error: 'Пользователь уже существует' });
    const hash = await bcrypt.hash(password, 12);
    const r = await db(
      `INSERT INTO users (username, password_hash, full_name, email, phone, role_id, organization_id, enterprise_id, res_unit_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, username, full_name`,
      [username, hash, full_name, email, phone, role_id, organization_id, enterprise_id, res_unit_id]);
    res.status(201).json(r.rows[0]);
  } catch (err) { console.error(err); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.get('/api/auth/me', auth, (req, res) => {
  const u = req.user;
  res.json({ id: u.id, username: u.username, full_name: u.full_name, email: u.email, phone: u.phone,
    role_name: u.role_name, role_display_name: u.role_display_name, role_level: u.role_level,
    general_permissions: u.general_permissions, organization_id: u.organization_id,
    enterprise_id: u.enterprise_id, res_unit_id: u.res_unit_id });
});

app.get('/api/auth/roles', auth, async (req, res) => {
  try {
    const r = await db('SELECT id, name, display_name, level, description, general_permissions FROM roles ORDER BY level, name');
    res.json(r.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) return res.status(400).json({ error: 'Оба пароля обязательны' });
    if (!(await bcrypt.compare(current_password, req.user.password_hash))) return res.status(400).json({ error: 'Неверный текущий пароль' });
    await db('UPDATE users SET password_hash=$1 WHERE id=$2', [await bcrypt.hash(new_password, 12), req.user.id]);
    res.json({ message: 'Пароль изменён' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============ ROUTES: ORG STRUCTURE ============

app.get('/api/org/organizations', auth, async (req, res) => {
  try { res.json((await db('SELECT * FROM organizations WHERE is_active=true ORDER BY name')).rows); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/org/organizations', auth, perm('can_create'), async (req, res) => {
  try { res.status(201).json(await orgCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/org/organizations/:id', auth, perm('can_edit'), async (req, res) => {
  try { res.json(await orgCRUD.update(req.params.id, req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/org/enterprises', auth, async (req, res) => {
  try {
    let sql = 'SELECT e.*, o.name as organization_name FROM enterprises e LEFT JOIN organizations o ON e.organization_id=o.id WHERE e.is_active=true';
    const p = [];
    if (req.user.role_level === 'enterprise' || req.user.role_level === 'res') {
      p.push(req.user.enterprise_id); sql += ` AND e.id=$${p.length}`;
    }
    sql += ' ORDER BY e.name';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/org/enterprises', auth, perm('can_create'), async (req, res) => {
  try { res.status(201).json(await entCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/org/enterprises/:id', auth, perm('can_edit'), async (req, res) => {
  try { res.json(await entCRUD.update(req.params.id, req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// --- СПБиПК ---
app.get('/api/org/spbipk', auth, async (req, res) => {
  try {
    let sql = `SELECT s.*, e.name as enterprise_name FROM spbipk s LEFT JOIN enterprises e ON s.enterprise_id=e.id WHERE s.is_active=true`;
    const p = [];
    if (req.user.role_level === 'enterprise') { p.push(req.user.enterprise_id); sql += ` AND s.enterprise_id=$${p.length}`; }
    if (req.query.enterprise_id) { p.push(req.query.enterprise_id); sql += ` AND s.enterprise_id=$${p.length}`; }
    sql += ' ORDER BY s.name';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/org/spbipk', auth, perm('can_create'), async (req, res) => {
  try { res.status(201).json(await spbipkCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/org/spbipk/:id', auth, perm('can_edit'), async (req, res) => {
  try { res.json(await spbipkCRUD.update(req.params.id, req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// --- РЭС/Служба ---
app.get('/api/org/res-units', auth, async (req, res) => {
  try {
    let sql = `SELECT r.*, e.name as enterprise_name, sp.name as spbipk_name
      FROM res_units r LEFT JOIN enterprises e ON r.enterprise_id=e.id
      LEFT JOIN spbipk sp ON r.spbipk_id=sp.id WHERE r.is_active=true`;
    const p = [];
    if (req.user.role_level === 'enterprise') { p.push(req.user.enterprise_id); sql += ` AND r.enterprise_id=$${p.length}`; }
    else if (req.user.role_level === 'res') { p.push(req.user.res_unit_id); sql += ` AND r.id=$${p.length}`; }
    if (req.query.enterprise_id) { p.push(req.query.enterprise_id); sql += ` AND r.enterprise_id=$${p.length}`; }
    if (req.query.spbipk_id) { p.push(req.query.spbipk_id); sql += ` AND r.spbipk_id=$${p.length}`; }
    sql += ' ORDER BY r.name';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/org/res-units', auth, perm('can_create'), async (req, res) => {
  try { res.status(201).json(await resCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/org/res-units/:id', auth, perm('can_edit'), async (req, res) => {
  try { res.json(await resCRUD.update(req.params.id, req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// --- Подразделения (под РЭС/Служба) ---
app.get('/api/org/departments', auth, async (req, res) => {
  try {
    let sql = `SELECT d.*, r.name as res_name FROM departments d LEFT JOIN res_units r ON d.res_unit_id=r.id WHERE d.is_active=true`;
    const p = [];
    if (req.query.res_unit_id) { p.push(req.query.res_unit_id); sql += ` AND d.res_unit_id=$${p.length}`; }
    sql += ' ORDER BY d.name';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/org/departments', auth, perm('can_create'), async (req, res) => {
  try { res.status(201).json(await deptCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/org/departments/:id', auth, perm('can_edit'), async (req, res) => {
  try { res.json(await deptCRUD.update(req.params.id, req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// --- Org Tree (full hierarchy) ---
app.get('/api/org/tree', auth, async (req, res) => {
  try {
    const orgs = (await db('SELECT * FROM organizations WHERE is_active=true')).rows;
    let entSql = 'SELECT * FROM enterprises WHERE is_active=true';
    let spSql = 'SELECT * FROM spbipk WHERE is_active=true';
    let resSql = 'SELECT * FROM res_units WHERE is_active=true';
    let deptSql = 'SELECT * FROM departments WHERE is_active=true';
    const p = [];
    if (req.user.role_level === 'enterprise') {
      p.push(req.user.enterprise_id);
      entSql += ` AND id=$1`; spSql += ` AND enterprise_id=$1`; resSql += ` AND enterprise_id=$1`;
    } else if (req.user.role_level === 'res') {
      p.push(req.user.res_unit_id); resSql += ` AND id=$1`;
    }
    const ents = (await db(entSql, req.user.role_level !== 'ia' ? p : [])).rows;
    const sps = (await db(spSql, req.user.role_level === 'enterprise' ? p : [])).rows;
    const units = (await db(resSql, p)).rows;
    const depts = (await db(deptSql)).rows;
    res.json(orgs.map(o => ({
      ...o, enterprises: ents.filter(e => e.organization_id === o.id).map(e => ({
        ...e,
        spbipk_list: sps.filter(s => s.enterprise_id === e.id),
        res_units: units.filter(r => r.enterprise_id === e.id).map(r => ({
          ...r, departments: depts.filter(d => d.res_unit_id === r.id)
        }))
      }))
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ ROUTES: SIZ CATEGORIES & ITEMS ============

app.get('/api/siz/categories', auth, async (req, res) => {
  try {
    res.json((await db(`SELECT c.*, (SELECT COUNT(*) FROM siz_items i WHERE i.category_id=c.id AND i.is_active=true) as items_count
      FROM siz_categories c WHERE c.is_active=true ORDER BY c.name`)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/siz/categories', auth, perm('can_create'), async (req, res) => {
  try { res.status(201).json(await catCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/siz/categories/:id', auth, perm('can_edit'), async (req, res) => {
  try { res.json(await catCRUD.update(req.params.id, req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/siz/categories/:id', auth, perm('can_delete'), async (req, res) => {
  try { res.json(await catCRUD.softDelete(req.params.id, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/siz/items', auth, async (req, res) => {
  try {
    let sql = `SELECT i.*, c.name as category_name, c.code as category_code FROM siz_items i
      LEFT JOIN siz_categories c ON i.category_id=c.id WHERE i.is_active=true`;
    const p = [];
    if (req.query.category_id) { p.push(req.query.category_id); sql += ` AND i.category_id=$${p.length}`; }
    if (req.query.search) { p.push(`%${req.query.search}%`); sql += ` AND (i.name ILIKE $${p.length} OR i.code ILIKE $${p.length})`; }
    sql += ' ORDER BY c.name, i.name';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/siz/items', auth, perm('can_create'), async (req, res) => {
  try { res.status(201).json(await itemCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/siz/items/:id', auth, perm('can_edit'), async (req, res) => {
  try { res.json(await itemCRUD.update(req.params.id, req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/siz/items/:id', auth, perm('can_delete'), async (req, res) => {
  try { res.json(await itemCRUD.softDelete(req.params.id, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ ROUTES: POSITIONS & NORMS ============

app.get('/api/positions', auth, async (req, res) => {
  try {
    res.json((await db(`SELECT p.*,
      (SELECT COUNT(*) FROM position_siz_norms n WHERE n.position_id=p.id AND n.is_active=true) as norms_count,
      (SELECT COUNT(*) FROM employees e WHERE e.position_id=p.id AND e.is_active=true) as employees_count
      FROM positions p WHERE p.is_active=true ORDER BY p.name`)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/positions', auth, perm('can_create'), async (req, res) => {
  try { res.status(201).json(await posCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/positions/:id', auth, perm('can_edit'), async (req, res) => {
  try { res.json(await posCRUD.update(req.params.id, req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/positions/:id', auth, perm('can_delete'), async (req, res) => {
  try { res.json(await posCRUD.softDelete(req.params.id, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/positions/:id/norms', auth, async (req, res) => {
  try {
    res.json((await db(`SELECT n.*, i.name as item_name, i.unit, i.wear_period_months, c.name as category_name
      FROM position_siz_norms n JOIN siz_items i ON n.siz_item_id=i.id
      LEFT JOIN siz_categories c ON i.category_id=c.id
      WHERE n.position_id=$1 AND n.is_active=true ORDER BY c.name, i.name`, [req.params.id])).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/positions/:id/norms', auth, perm('can_create'), async (req, res) => {
  try {
    const { siz_item_id, quantity, issue_period_months, extra } = req.body;
    const r = await db(
      `INSERT INTO position_siz_norms (position_id, siz_item_id, quantity, issue_period_months, extra)
       VALUES ($1,$2,$3,$4,$5) ON CONFLICT (position_id, siz_item_id)
       DO UPDATE SET quantity=$3, issue_period_months=$4, extra=$5, is_active=true RETURNING *`,
      [req.params.id, siz_item_id, quantity || 1, issue_period_months || 12, JSON.stringify(extra || {})]);
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ ROUTES: TON (Типовые отраслевые нормы) ============

// Получить все нормы с группировкой — плоский список
app.get('/api/ton', auth, async (req, res) => {
  try {
    let sql = `SELECT n.id, n.position_id, n.siz_item_id, n.quantity, n.issue_period_months,
      p.name as position_name, p.code as position_code,
      i.name as item_name, i.code as item_code, i.unit, i.wear_period_months,
      c.name as category_name
      FROM position_siz_norms n
      JOIN positions p ON n.position_id = p.id AND p.is_active = true
      JOIN siz_items i ON n.siz_item_id = i.id AND i.is_active = true
      LEFT JOIN siz_categories c ON i.category_id = c.id
      WHERE n.is_active = true`;
    const params = [];
    if (req.query.position_id) {
      params.push(req.query.position_id);
      sql += ` AND n.position_id = $${params.length}`;
    }
    if (req.query.category_id) {
      params.push(req.query.category_id);
      sql += ` AND i.category_id = $${params.length}`;
    }
    sql += ' ORDER BY p.name, c.name, i.name';
    res.json((await db(sql, params)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Удалить норму из ТОН
app.delete('/api/ton/:id', auth, perm('can_delete'), async (req, res) => {
  try {
    const r = await db('UPDATE position_siz_norms SET is_active = false WHERE id = $1 RETURNING *', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Норма не найдена' });
    await audit(req.user.id, 'position_siz_norms', req.params.id, 'delete', {}, req.ip);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Получить разрешённые СИЗ для конкретного сотрудника (по его должности из ТОН)
app.get('/api/ton/items-for-employee/:employeeId', auth, async (req, res) => {
  try {
    const sql = `SELECT i.id, i.name, i.code, i.unit, i.wear_period_months,
      c.name as category_name, n.quantity as norm_quantity, n.issue_period_months
      FROM position_siz_norms n
      JOIN siz_items i ON n.siz_item_id = i.id AND i.is_active = true
      LEFT JOIN siz_categories c ON i.category_id = c.id
      JOIN employees e ON e.position_id = n.position_id AND e.id = $1
      WHERE n.is_active = true
      ORDER BY c.name, i.name`;
    res.json((await db(sql, [req.params.employeeId])).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ ROUTES: SIZE REFERENCES ============

app.get('/api/sizes', auth, async (req, res) => {
  try {
    let sql = 'SELECT * FROM size_references';
    const p = [];
    if (req.query.category_type) {
      p.push(req.query.category_type);
      sql += ` WHERE category_type = $1`;
    }
    sql += ' ORDER BY category_type, sort_order';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ ROUTES: WAREHOUSES ============

// Список складов
app.get('/api/warehouses', auth, async (req, res) => {
  try {
    let sql = `SELECT w.*, sp.name as spbipk_name, r.name as res_name, e.name as enterprise_name
      FROM warehouses w
      LEFT JOIN spbipk sp ON w.spbipk_id = sp.id
      LEFT JOIN res_units r ON w.res_unit_id = r.id
      LEFT JOIN enterprises e ON w.enterprise_id = e.id
      WHERE w.is_active = true`;
    const p = [];
    if (req.query.warehouse_type) { p.push(req.query.warehouse_type); sql += ` AND w.warehouse_type = $${p.length}`; }
    if (req.query.enterprise_id) { p.push(req.query.enterprise_id); sql += ` AND w.enterprise_id = $${p.length}`; }
    if (req.user.role_level === 'enterprise') { p.push(req.user.enterprise_id); sql += ` AND w.enterprise_id = $${p.length}`; }
    else if (req.user.role_level === 'res') { p.push(req.user.res_unit_id); sql += ` AND (w.res_unit_id = $${p.length})`; }
    sql += ' ORDER BY w.warehouse_type, w.name';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Создать склад
app.post('/api/warehouses', auth, perm('can_create'), async (req, res) => {
  try {
    const { name, warehouse_type, spbipk_id, res_unit_id, enterprise_id } = req.body;
    if (!name || !warehouse_type) return res.status(400).json({ error: 'name и warehouse_type обязательны' });
    const r = await db(
      `INSERT INTO warehouses (name, warehouse_type, spbipk_id, res_unit_id, enterprise_id) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [name, warehouse_type, spbipk_id || null, res_unit_id || null, enterprise_id || null]);
    await audit(req.user.id, 'warehouses', r.rows[0].id, 'create', req.body, req.ip);
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Остатки склада (сгруппированные для дерева: item → gender → size → qty)
app.get('/api/warehouses/:id/stock', auth, async (req, res) => {
  try {
    const sql = `SELECT ws.id, ws.siz_item_id, ws.size_value, ws.quantity,
      i.name as item_name, i.code as item_code, i.unit, i.gender as item_gender, i.season,
      i.exploitation_years, c.name as category_name, c.code as category_code
      FROM warehouse_stock ws
      JOIN siz_items i ON ws.siz_item_id = i.id
      LEFT JOIN siz_categories c ON i.category_id = c.id
      WHERE ws.warehouse_id = $1 AND ws.quantity > 0
      ORDER BY c.name, i.name, i.gender, ws.size_value`;
    res.json((await db(sql, [req.params.id])).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Приход на склад (receipt)
app.post('/api/warehouses/:id/receipt', auth, perm('can_create'), async (req, res) => {
  try {
    const { siz_item_id, size_value, quantity, document_reference, notes, movement_date } = req.body;
    if (!siz_item_id || !quantity || quantity < 1)
      return res.status(400).json({ error: 'siz_item_id и quantity обязательны' });
    const sv = size_value || '';
    // Обновить остаток
    await db(`INSERT INTO warehouse_stock (warehouse_id, siz_item_id, size_value, quantity)
      VALUES ($1,$2,$3,$4) ON CONFLICT (warehouse_id, siz_item_id, size_value)
      DO UPDATE SET quantity = warehouse_stock.quantity + $4`,
      [req.params.id, siz_item_id, sv, quantity]);
    // Записать движение
    const r = await db(`INSERT INTO stock_movements
      (movement_type, siz_item_id, size_value, quantity, to_warehouse_id, document_reference, notes, moved_by, movement_date)
      VALUES ('receipt',$1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [siz_item_id, sv, quantity, req.params.id, document_reference||null, notes||null, req.user.id,
       movement_date || new Date().toISOString().split('T')[0]]);
    await audit(req.user.id, 'stock_movements', r.rows[0].id, 'create', req.body, req.ip);
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Перемещение между складами (transfer)
app.post('/api/warehouses/transfer', auth, perm('can_create'), async (req, res) => {
  try {
    const { from_warehouse_id, to_warehouse_id, siz_item_id, size_value, quantity, document_reference, notes, movement_date } = req.body;
    if (!from_warehouse_id || !to_warehouse_id || !siz_item_id || !quantity)
      return res.status(400).json({ error: 'Все поля обязательны' });
    const sv = size_value || '';
    // Проверить остаток
    const stock = await db('SELECT quantity FROM warehouse_stock WHERE warehouse_id=$1 AND siz_item_id=$2 AND size_value=$3',
      [from_warehouse_id, siz_item_id, sv]);
    const available = stock.rows[0]?.quantity || 0;
    if (available < quantity) return res.status(400).json({ error: `Недостаточно на складе (есть: ${available})` });
    // Минус с источника
    await db('UPDATE warehouse_stock SET quantity = quantity - $1 WHERE warehouse_id=$2 AND siz_item_id=$3 AND size_value=$4',
      [quantity, from_warehouse_id, siz_item_id, sv]);
    // Плюс на приёмник
    await db(`INSERT INTO warehouse_stock (warehouse_id, siz_item_id, size_value, quantity)
      VALUES ($1,$2,$3,$4) ON CONFLICT (warehouse_id, siz_item_id, size_value)
      DO UPDATE SET quantity = warehouse_stock.quantity + $4`,
      [to_warehouse_id, siz_item_id, sv, quantity]);
    // Движение
    const r = await db(`INSERT INTO stock_movements
      (movement_type, siz_item_id, size_value, quantity, from_warehouse_id, to_warehouse_id, document_reference, notes, moved_by, movement_date)
      VALUES ('transfer',$1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [siz_item_id, sv, quantity, from_warehouse_id, to_warehouse_id, document_reference||null, notes||null, req.user.id,
       movement_date || new Date().toISOString().split('T')[0]]);
    await audit(req.user.id, 'stock_movements', r.rows[0].id, 'create', req.body, req.ip);
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Выдача сотруднику (issue) — со склада РЭС
app.post('/api/warehouses/:id/issue', auth, perm('can_create'), async (req, res) => {
  try {
    const { employee_id, siz_item_id, size_value, quantity, document_reference, notes, movement_date } = req.body;
    if (!employee_id || !siz_item_id || !quantity)
      return res.status(400).json({ error: 'employee_id, siz_item_id, quantity обязательны' });
    const sv = size_value || '';
    const md = movement_date || new Date().toISOString().split('T')[0];
    // Проверить остаток
    const stock = await db('SELECT quantity FROM warehouse_stock WHERE warehouse_id=$1 AND siz_item_id=$2 AND size_value=$3',
      [req.params.id, siz_item_id, sv]);
    const available = stock.rows[0]?.quantity || 0;
    if (available < quantity) return res.status(400).json({ error: `Недостаточно на складе (есть: ${available})` });
    // Минус со склада
    await db('UPDATE warehouse_stock SET quantity = quantity - $1 WHERE warehouse_id=$2 AND siz_item_id=$3 AND size_value=$4',
      [quantity, req.params.id, siz_item_id, sv]);
    // Получить exploitation_years для расчёта
    const itemR = await db('SELECT exploitation_years FROM siz_items WHERE id=$1', [siz_item_id]);
    const expYears = itemR.rows[0]?.exploitation_years;
    // Записать на сотрудника
    await db(`INSERT INTO employee_siz (employee_id, siz_item_id, size_value, quantity, issued_date, exploitation_start, from_warehouse_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [employee_id, siz_item_id, sv, quantity, md, expYears ? md : null, req.params.id]);
    // Движение
    const r = await db(`INSERT INTO stock_movements
      (movement_type, siz_item_id, size_value, quantity, from_warehouse_id, employee_id, document_reference, notes, moved_by, movement_date)
      VALUES ('issue',$1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [siz_item_id, sv, quantity, req.params.id, employee_id, document_reference||null, notes||null, req.user.id, md]);
    await audit(req.user.id, 'stock_movements', r.rows[0].id, 'create', req.body, req.ip);
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Возврат от сотрудника на склад (return)
app.post('/api/warehouses/:id/return', auth, perm('can_create'), async (req, res) => {
  try {
    const { employee_siz_id, quantity, document_reference, notes, movement_date } = req.body;
    if (!employee_siz_id || !quantity)
      return res.status(400).json({ error: 'employee_siz_id и quantity обязательны' });
    const md = movement_date || new Date().toISOString().split('T')[0];
    // Найти запись
    const es = await db('SELECT * FROM employee_siz WHERE id=$1 AND status=$2', [employee_siz_id, 'active']);
    if (!es.rows.length) return res.status(404).json({ error: 'Запись не найдена или уже возвращена' });
    const rec = es.rows[0];
    if (quantity > rec.quantity) return res.status(400).json({ error: `У сотрудника только ${rec.quantity}` });
    // Считаем паузу эксплуатации
    let pausedDays = rec.exploitation_paused_days || 0;
    if (rec.exploitation_start) {
      const startDate = new Date(rec.exploitation_start);
      const now = new Date(md);
      const usedDays = Math.floor((now - startDate) / 86400000);
      pausedDays = usedDays; // сохраняем сколько дней эксплуатировалось
    }
    if (quantity >= rec.quantity) {
      // Полный возврат
      await db('UPDATE employee_siz SET status=$1, returned_date=$2, exploitation_paused_days=$3 WHERE id=$4',
        ['returned', md, pausedDays, employee_siz_id]);
    } else {
      // Частичный возврат
      await db('UPDATE employee_siz SET quantity = quantity - $1 WHERE id=$2', [quantity, employee_siz_id]);
    }
    // Плюс на склад
    await db(`INSERT INTO warehouse_stock (warehouse_id, siz_item_id, size_value, quantity)
      VALUES ($1,$2,$3,$4) ON CONFLICT (warehouse_id, siz_item_id, size_value)
      DO UPDATE SET quantity = warehouse_stock.quantity + $4`,
      [req.params.id, rec.siz_item_id, rec.size_value, quantity]);
    // Движение
    const r = await db(`INSERT INTO stock_movements
      (movement_type, siz_item_id, size_value, quantity, to_warehouse_id, employee_id, document_reference, notes, moved_by, movement_date)
      VALUES ('return',$1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [rec.siz_item_id, rec.size_value, quantity, req.params.id, rec.employee_id,
       document_reference||null, notes||null, req.user.id, md]);
    await audit(req.user.id, 'stock_movements', r.rows[0].id, 'create', req.body, req.ip);
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// История движений по складу
app.get('/api/warehouses/:id/movements', auth, async (req, res) => {
  try {
    const sql = `SELECT m.*, i.name as item_name, i.unit, c.name as category_name,
      fw.name as from_warehouse_name, tw.name as to_warehouse_name,
      e.last_name, e.first_name, e.middle_name, u.full_name as moved_by_name
      FROM stock_movements m
      JOIN siz_items i ON m.siz_item_id = i.id
      LEFT JOIN siz_categories c ON i.category_id = c.id
      LEFT JOIN warehouses fw ON m.from_warehouse_id = fw.id
      LEFT JOIN warehouses tw ON m.to_warehouse_id = tw.id
      LEFT JOIN employees e ON m.employee_id = e.id
      LEFT JOIN users u ON m.moved_by = u.id
      WHERE m.from_warehouse_id = $1 OR m.to_warehouse_id = $1
      ORDER BY m.created_at DESC LIMIT 200`;
    res.json((await db(sql, [req.params.id])).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// СИЗ на руках у конкретного сотрудника (для карточки)
app.get('/api/employee-siz/:employeeId', auth, async (req, res) => {
  try {
    const sql = `SELECT es.*, i.name as item_name, i.unit, i.exploitation_years,
      i.gender as item_gender, i.season, c.name as category_name, w.name as warehouse_name
      FROM employee_siz es
      JOIN siz_items i ON es.siz_item_id = i.id
      LEFT JOIN siz_categories c ON i.category_id = c.id
      LEFT JOIN warehouses w ON es.from_warehouse_id = w.id
      WHERE es.employee_id = $1 AND es.status = 'active'
      ORDER BY c.name, i.name`;
    res.json((await db(sql, [req.params.employeeId])).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Выгрузка остатков склада в Excel-совместимый JSON
app.get('/api/warehouses/:id/export', auth, async (req, res) => {
  try {
    const sql = `SELECT i.name as item_name, c.name as category_name,
      i.gender, i.season, ws.size_value, ws.quantity, i.unit, i.exploitation_years
      FROM warehouse_stock ws
      JOIN siz_items i ON ws.siz_item_id = i.id
      LEFT JOIN siz_categories c ON i.category_id = c.id
      WHERE ws.warehouse_id = $1 AND ws.quantity > 0
      ORDER BY c.name, i.name, i.gender, ws.size_value`;
    res.json((await db(sql, [req.params.id])).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ ROUTES: EMPLOYEES ============

app.get('/api/employees', auth, async (req, res) => {
  try {
    let sql = `SELECT e.*, p.name as position_name, r.name as res_name, ent.name as enterprise_name,
      d.name as department_name
      FROM employees e LEFT JOIN positions p ON e.position_id=p.id
      LEFT JOIN res_units r ON e.res_unit_id=r.id LEFT JOIN enterprises ent ON e.enterprise_id=ent.id
      LEFT JOIN departments d ON e.department_id=d.id
      WHERE e.is_active=true`;
    const p = [];
    if (req.user.role_level === 'enterprise') { p.push(req.user.enterprise_id); sql += ` AND e.enterprise_id=$${p.length}`; }
    else if (req.user.role_level === 'res') { p.push(req.user.res_unit_id); sql += ` AND e.res_unit_id=$${p.length}`; }
    if (req.query.res_unit_id) { p.push(req.query.res_unit_id); sql += ` AND e.res_unit_id=$${p.length}`; }
    if (req.query.enterprise_id) { p.push(req.query.enterprise_id); sql += ` AND e.enterprise_id=$${p.length}`; }
    if (req.query.department_id) { p.push(req.query.department_id); sql += ` AND e.department_id=$${p.length}`; }
    if (req.query.position_id) { p.push(req.query.position_id); sql += ` AND e.position_id=$${p.length}`; }
    if (req.query.search) { p.push(`%${req.query.search}%`); sql += ` AND (e.last_name ILIKE $${p.length} OR e.first_name ILIKE $${p.length} OR e.employee_number ILIKE $${p.length})`; }
    sql += ' ORDER BY e.last_name, e.first_name';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/employees/:id', auth, async (req, res) => {
  try {
    const emp = (await db(`SELECT e.*, p.name as position_name, r.name as res_name, ent.name as enterprise_name,
      d.name as department_name
      FROM employees e LEFT JOIN positions p ON e.position_id=p.id
      LEFT JOIN res_units r ON e.res_unit_id=r.id LEFT JOIN enterprises ent ON e.enterprise_id=ent.id
      LEFT JOIN departments d ON e.department_id=d.id
      WHERE e.id=$1`, [req.params.id])).rows[0];
    if (!emp) return res.status(404).json({ error: 'Сотрудник не найден' });

    const norms = (await db(`SELECT n.*, i.name as item_name, i.unit, c.name as category_name
      FROM position_siz_norms n JOIN siz_items i ON n.siz_item_id=i.id
      LEFT JOIN siz_categories c ON i.category_id=c.id WHERE n.position_id=$1 AND n.is_active=true`, [emp.position_id])).rows;

    const transactions = (await db(`SELECT t.*, i.name as item_name, i.unit, c.name as category_name, u.full_name as issued_by_name
      FROM siz_transactions t JOIN siz_items i ON t.siz_item_id=i.id
      LEFT JOIN siz_categories c ON i.category_id=c.id LEFT JOIN users u ON t.issued_by=u.id
      WHERE t.employee_id=$1 ORDER BY t.transaction_date DESC, t.created_at DESC`, [req.params.id])).rows;

    const balance = (await db(`SELECT i.id as item_id, i.name as item_name, i.unit, c.name as category_name,
      SUM(CASE WHEN t.transaction_type='issue' THEN t.quantity WHEN t.transaction_type IN ('return','write_off') THEN -t.quantity ELSE 0 END) as on_hand,
      MAX(CASE WHEN t.transaction_type='issue' THEN t.valid_until END) as valid_until,
      MAX(CASE WHEN t.transaction_type='issue' THEN t.transaction_date END) as last_issued
      FROM siz_transactions t JOIN siz_items i ON t.siz_item_id=i.id LEFT JOIN siz_categories c ON i.category_id=c.id
      WHERE t.employee_id=$1 GROUP BY i.id, i.name, i.unit, c.name
      HAVING SUM(CASE WHEN t.transaction_type='issue' THEN t.quantity WHEN t.transaction_type IN ('return','write_off') THEN -t.quantity ELSE 0 END) > 0`,
      [req.params.id])).rows;

    res.json({ ...emp, norms, transactions, balance });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/employees', auth, perm('can_create'), async (req, res) => {
  try { res.status(201).json(await empCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/employees/:id', auth, perm('can_edit'), async (req, res) => {
  try { res.json(await empCRUD.update(req.params.id, req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/employees/:id', auth, perm('can_delete'), async (req, res) => {
  try { res.json(await empCRUD.softDelete(req.params.id, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ ROUTES: TRANSACTIONS ============

app.get('/api/transactions', auth, async (req, res) => {
  try {
    let sql = `SELECT t.*, e.last_name, e.first_name, e.middle_name, e.employee_number,
      i.name as item_name, i.unit, c.name as category_name, u.full_name as issued_by_name
      FROM siz_transactions t JOIN employees e ON t.employee_id=e.id
      JOIN siz_items i ON t.siz_item_id=i.id LEFT JOIN siz_categories c ON i.category_id=c.id
      LEFT JOIN users u ON t.issued_by=u.id WHERE 1=1`;
    const p = [];
    if (req.user.role_level === 'enterprise') { p.push(req.user.enterprise_id); sql += ` AND e.enterprise_id=$${p.length}`; }
    else if (req.user.role_level === 'res') { p.push(req.user.res_unit_id); sql += ` AND e.res_unit_id=$${p.length}`; }
    if (req.query.employee_id) { p.push(req.query.employee_id); sql += ` AND t.employee_id=$${p.length}`; }
    if (req.query.transaction_type) { p.push(req.query.transaction_type); sql += ` AND t.transaction_type=$${p.length}`; }
    if (req.query.date_from) { p.push(req.query.date_from); sql += ` AND t.transaction_date>=$${p.length}`; }
    if (req.query.date_to) { p.push(req.query.date_to); sql += ` AND t.transaction_date<=$${p.length}`; }
    sql += ' ORDER BY t.transaction_date DESC, t.created_at DESC';
    if (req.query.limit) { p.push(parseInt(req.query.limit)); sql += ` LIMIT $${p.length}`; }
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/transactions', auth, perm('can_create'), async (req, res) => {
  try {
    const { employee_id, siz_item_id, transaction_type, quantity, transaction_date, valid_until, document_reference, notes, extra } = req.body;
    if (!employee_id || !siz_item_id || !transaction_type)
      return res.status(400).json({ error: 'employee_id, siz_item_id, transaction_type обязательны' });
    const r = await db(
      `INSERT INTO siz_transactions (employee_id, siz_item_id, transaction_type, quantity, transaction_date, valid_until, issued_by, document_reference, notes, extra)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [employee_id, siz_item_id, transaction_type, quantity || 1,
        transaction_date || new Date().toISOString().split('T')[0], valid_until || null,
        req.user.id, document_reference || null, notes || null, JSON.stringify(extra || {})]);
    await audit(req.user.id, 'siz_transactions', r.rows[0].id, 'create', req.body, req.ip);
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/transactions/reports/expired', auth, async (req, res) => {
  try {
    let sql = `SELECT DISTINCT ON (t.employee_id, t.siz_item_id) t.*, e.last_name, e.first_name, e.middle_name,
      i.name as item_name, r.name as res_name FROM siz_transactions t
      JOIN employees e ON t.employee_id=e.id JOIN siz_items i ON t.siz_item_id=i.id
      LEFT JOIN res_units r ON e.res_unit_id=r.id
      WHERE t.transaction_type='issue' AND t.valid_until < CURRENT_DATE AND t.valid_until IS NOT NULL`;
    const p = [];
    if (req.user.role_level === 'enterprise') { p.push(req.user.enterprise_id); sql += ` AND e.enterprise_id=$${p.length}`; }
    else if (req.user.role_level === 'res') { p.push(req.user.res_unit_id); sql += ` AND e.res_unit_id=$${p.length}`; }
    sql += ' ORDER BY t.employee_id, t.siz_item_id, t.transaction_date DESC';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/transactions/reports/summary', auth, async (req, res) => {
  try {
    let sql = `SELECT r.name as res_name, r.id as res_unit_id,
      COUNT(DISTINCT e.id) as employees_count,
      COUNT(DISTINCT CASE WHEN t.transaction_type='issue' THEN t.id END) as total_issued,
      COUNT(DISTINCT CASE WHEN t.valid_until < CURRENT_DATE AND t.transaction_type='issue' THEN t.id END) as expired_count
      FROM res_units r LEFT JOIN employees e ON e.res_unit_id=r.id AND e.is_active=true
      LEFT JOIN siz_transactions t ON t.employee_id=e.id WHERE r.is_active=true`;
    const p = [];
    if (req.user.role_level === 'enterprise') { p.push(req.user.enterprise_id); sql += ` AND r.enterprise_id=$${p.length}`; }
    else if (req.user.role_level === 'res') { p.push(req.user.res_unit_id); sql += ` AND r.id=$${p.length}`; }
    sql += ' GROUP BY r.id, r.name ORDER BY r.name';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ ROUTES: ADMIN ============

app.get('/api/admin/users', auth, levelCheck(['ia']), async (req, res) => {
  try {
    res.json((await db(`SELECT u.id, u.username, u.full_name, u.email, u.phone, u.is_active, u.last_login,
      u.role_id, u.organization_id, u.enterprise_id, u.res_unit_id,
      r.display_name as role_name, r.level as role_level,
      o.name as organization_name, e.name as enterprise_name, ru.name as res_name
      FROM users u LEFT JOIN roles r ON u.role_id=r.id LEFT JOIN organizations o ON u.organization_id=o.id
      LEFT JOIN enterprises e ON u.enterprise_id=e.id LEFT JOIN res_units ru ON u.res_unit_id=ru.id
      ORDER BY u.full_name`)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/users/:id', auth, levelCheck(['ia']), async (req, res) => {
  try {
    const { full_name, email, phone, role_id, organization_id, enterprise_id, res_unit_id, new_password } = req.body;
    const sets = []; const vals = []; let i = 1;
    if (full_name !== undefined) { sets.push(`full_name=$${i}`); vals.push(full_name); i++; }
    if (email !== undefined) { sets.push(`email=$${i}`); vals.push(email); i++; }
    if (phone !== undefined) { sets.push(`phone=$${i}`); vals.push(phone); i++; }
    if (role_id !== undefined) { sets.push(`role_id=$${i}`); vals.push(role_id); i++; }
    if (organization_id !== undefined) { sets.push(`organization_id=$${i}`); vals.push(organization_id || null); i++; }
    if (enterprise_id !== undefined) { sets.push(`enterprise_id=$${i}`); vals.push(enterprise_id || null); i++; }
    if (res_unit_id !== undefined) { sets.push(`res_unit_id=$${i}`); vals.push(res_unit_id || null); i++; }
    if (new_password) { sets.push(`password_hash=$${i}`); vals.push(await bcrypt.hash(new_password, 12)); i++; }
    if (!sets.length) return res.status(400).json({ error: 'Нет данных для обновления' });
    vals.push(req.params.id);
    const r = await db(`UPDATE users SET ${sets.join(',')} WHERE id=$${i} RETURNING id, username, full_name`, vals);
    if (!r.rows.length) return res.status(404).json({ error: 'Пользователь не найден' });
    await audit(req.user.id, 'users', req.params.id, 'update', { full_name, email, role_id }, req.ip);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/users/:id', auth, levelCheck(['ia']), async (req, res) => {
  try {
    const { confirm_password } = req.body || {};
    if (!confirm_password) return res.status(400).json({ error: 'Требуется пароль подтверждения' });
    if (confirm_password !== (process.env.DELETE_PASSWORD || '2233'))
      return res.status(403).json({ error: 'Неверный пароль подтверждения' });
    const r = await db('UPDATE users SET is_active=false WHERE id=$1 RETURNING id, username', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Пользователь не найден' });
    await audit(req.user.id, 'users', req.params.id, 'delete', {}, req.ip);
    res.json({ message: 'Пользователь деактивирован', user: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/field-rules', auth, levelCheck(['ia']), async (req, res) => {
  try {
    res.json((await db(`SELECT far.*, r.display_name as role_name, r.level as role_level
      FROM field_access_rules far JOIN roles r ON far.role_id=r.id ORDER BY r.level, r.name, far.target_table`)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/admin/field-rules', auth, levelCheck(['ia']), async (req, res) => {
  try {
    const { role_id, target_table, field_name, access_level, conditions } = req.body;
    const r = await db(
      `INSERT INTO field_access_rules (role_id, target_table, field_name, access_level, conditions)
       VALUES ($1,$2,$3,$4,$5) ON CONFLICT (role_id, target_table, field_name)
       DO UPDATE SET access_level=$4, conditions=$5 RETURNING *`,
      [role_id, target_table, field_name || '*', access_level || 'read', JSON.stringify(conditions || {})]);
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/admin/field-rules/:id', auth, levelCheck(['ia']), async (req, res) => {
  try { res.json((await db('DELETE FROM field_access_rules WHERE id=$1 RETURNING *', [req.params.id])).rows[0]); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/audit', auth, levelCheck(['ia', 'enterprise']), async (req, res) => {
  try {
    let sql = `SELECT a.*, u.full_name as user_name, u.username FROM audit_log a LEFT JOIN users u ON a.user_id=u.id WHERE 1=1`;
    const p = [];
    if (req.query.table_name) { p.push(req.query.table_name); sql += ` AND a.table_name=$${p.length}`; }
    if (req.query.action) { p.push(req.query.action); sql += ` AND a.action=$${p.length}`; }
    sql += ' ORDER BY a.created_at DESC LIMIT 100';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/schema-info', auth, levelCheck(['ia']), async (req, res) => {
  try {
    const r = await db(`SELECT table_name, column_name, data_type FROM information_schema.columns
      WHERE table_schema='public' AND table_name IN ('employees','siz_items','siz_transactions','positions','position_siz_norms')
      ORDER BY table_name, ordinal_position`);
    const schema = {};
    r.rows.forEach(row => {
      if (!schema[row.table_name]) schema[row.table_name] = [];
      schema[row.table_name].push({ name: row.column_name, type: row.data_type });
    });
    res.json(schema);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ HEALTH CHECK ============
app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

// ============ SPA FALLBACK ============
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ============ DB INIT & START ============

async function initDB() {
  try {
    const sqlPath = path.join(__dirname, 'init.sql');
    if (fs.existsSync(sqlPath)) {
      const sql = fs.readFileSync(sqlPath, 'utf8');
      await pool.query(sql);
      console.log('DB schema applied');
    }

    // Migration: add spbipk table and update hierarchy
    await pool.query(
      "CREATE TABLE IF NOT EXISTS size_references (" +
      "id UUID PRIMARY KEY DEFAULT gen_random_uuid()," +
      "category_type VARCHAR(20) NOT NULL," +
      "size_value VARCHAR(30) NOT NULL," +
      "sort_order INTEGER DEFAULT 0," +
      "UNIQUE(category_type, size_value))"
    );
    await pool.query("ALTER TABLE siz_items ADD COLUMN IF NOT EXISTS gender VARCHAR(10)");
    await pool.query("ALTER TABLE siz_items ADD COLUMN IF NOT EXISTS season VARCHAR(10)");
    await pool.query("ALTER TABLE siz_items ADD COLUMN IF NOT EXISTS exploitation_years NUMERIC");
    await pool.query(
      "CREATE TABLE IF NOT EXISTS warehouses (" +
      "id UUID PRIMARY KEY DEFAULT gen_random_uuid()," +
      "name VARCHAR(255) NOT NULL," +
      "warehouse_type VARCHAR(20) NOT NULL," +
      "spbipk_id UUID REFERENCES spbipk(id)," +
      "res_unit_id UUID REFERENCES res_units(id)," +
      "enterprise_id UUID REFERENCES enterprises(id)," +
      "is_active BOOLEAN DEFAULT true," +
      "created_at TIMESTAMPTZ DEFAULT NOW())"
    );
    await pool.query(
      "CREATE TABLE IF NOT EXISTS warehouse_stock (" +
      "id UUID PRIMARY KEY DEFAULT gen_random_uuid()," +
      "warehouse_id UUID NOT NULL REFERENCES warehouses(id)," +
      "siz_item_id UUID NOT NULL REFERENCES siz_items(id)," +
      "size_value VARCHAR(30) DEFAULT ''," +
      "quantity INTEGER NOT NULL DEFAULT 0," +
      "UNIQUE(warehouse_id, siz_item_id, size_value))"
    );
    await pool.query(
      "CREATE TABLE IF NOT EXISTS stock_movements (" +
      "id UUID PRIMARY KEY DEFAULT gen_random_uuid()," +
      "movement_type VARCHAR(20) NOT NULL," +
      "siz_item_id UUID NOT NULL REFERENCES siz_items(id)," +
      "size_value VARCHAR(30) DEFAULT ''," +
      "quantity INTEGER NOT NULL," +
      "from_warehouse_id UUID REFERENCES warehouses(id)," +
      "to_warehouse_id UUID REFERENCES warehouses(id)," +
      "employee_id UUID REFERENCES employees(id)," +
      "document_reference VARCHAR(255)," +
      "notes TEXT," +
      "moved_by UUID REFERENCES users(id)," +
      "movement_date DATE NOT NULL DEFAULT CURRENT_DATE," +
      "created_at TIMESTAMPTZ DEFAULT NOW())"
    );
    await pool.query(
      "CREATE TABLE IF NOT EXISTS employee_siz (" +
      "id UUID PRIMARY KEY DEFAULT gen_random_uuid()," +
      "employee_id UUID NOT NULL REFERENCES employees(id)," +
      "siz_item_id UUID NOT NULL REFERENCES siz_items(id)," +
      "size_value VARCHAR(30) DEFAULT ''," +
      "quantity INTEGER NOT NULL DEFAULT 1," +
      "issued_date DATE NOT NULL DEFAULT CURRENT_DATE," +
      "exploitation_start DATE," +
      "exploitation_paused_days INTEGER DEFAULT 0," +
      "status VARCHAR(20) DEFAULT 'active'," +
      "returned_date DATE," +
      "from_warehouse_id UUID REFERENCES warehouses(id)," +
      "created_at TIMESTAMPTZ DEFAULT NOW())"
    );
    await pool.query(
      "INSERT INTO size_references (category_type, size_value, sort_order) VALUES " +
      "('shoes','35',1),('shoes','36',2),('shoes','37',3),('shoes','38',4),('shoes','39',5)," +
      "('shoes','40',6),('shoes','41',7),('shoes','42',8),('shoes','43',9),('shoes','44',10)," +
      "('shoes','45',11),('shoes','46',12),('shoes','47',13),('shoes','48',14),('shoes','49',15)," +
      "('clothing','40-42/158-164',1),('clothing','40-42/170-176',2),('clothing','40-42/182-188',3),('clothing','40-42/194-200',4)," +
      "('clothing','44-46/158-164',5),('clothing','44-46/170-176',6),('clothing','44-46/182-188',7),('clothing','44-46/194-200',8)," +
      "('clothing','48-50/158-164',9),('clothing','48-50/170-176',10),('clothing','48-50/182-188',11),('clothing','48-50/194-200',12)," +
      "('clothing','52-54/158-164',13),('clothing','52-54/170-176',14),('clothing','52-54/182-188',15),('clothing','52-54/194-200',16)," +
      "('clothing','56-58/158-164',17),('clothing','56-58/170-176',18),('clothing','56-58/182-188',19),('clothing','56-58/194-200',20)," +
      "('clothing','60-62/158-164',21),('clothing','60-62/170-176',22),('clothing','60-62/182-188',23),('clothing','60-62/194-200',24)," +
      "('clothing','64-66/158-164',25),('clothing','64-66/170-176',26),('clothing','64-66/182-188',27),('clothing','64-66/194-200',28)," +
      "('clothing','68-70/158-164',29),('clothing','68-70/170-176',30),('clothing','68-70/182-188',31),('clothing','68-70/194-200',32)," +
      "('clothing','72-74/158-164',33),('clothing','72-74/170-176',34),('clothing','72-74/182-188',35),('clothing','72-74/194-200',36)," +
      "('head','Универсальный',1)," +
      "('gloves','Универсальный',1)," +
      "('consumable','Ручной ввод',1)" +
      " ON CONFLICT (category_type, size_value) DO NOTHING"
    );
    console.log('Migration: warehouses + sizes applied');

    // Create default admin
    const roleR = await db("SELECT id FROM roles WHERE name='admin_ia'");
    const orgR = await db("SELECT id FROM organizations WHERE code='IA'");
    if (roleR.rows.length) {
      const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 12);
      await db(`INSERT INTO users (username, password_hash, full_name, email, role_id, organization_id)
        VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (username) DO NOTHING`,
        ['admin', hash, 'Администратор системы', 'admin@siz.local', roleR.rows[0].id, orgR.rows[0]?.id]);
      console.log('Admin user ready (login: admin)');
    }
  } catch (e) { console.error('DB init error:', e.message); }
}

initDB().then(() => {
  app.listen(PORT, () => console.log(`SIZ server → http://localhost:${PORT}`));
});
