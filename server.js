// ============================================
// СИЗ: Учёт и движение — Сервер
// Россети-Юг / Кубаньэнерго
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

// Hierarchy check — supports ia, enterprise, spbipk, res
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
        enterprise_id: user.enterprise_id, res_unit_id: user.res_unit_id, spbipk_id: user.spbipk_id }
    });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/auth/register', auth, async (req, res) => {
  try {
    if (!['ia', 'spbipk'].includes(req.user.role_level) || !req.user.general_permissions?.can_create)
      return res.status(403).json({ error: 'Недостаточно прав' });
    const { username, password, full_name, email, phone, role_id, organization_id, enterprise_id, res_unit_id, spbipk_id } = req.body;
    if (!username || !password || !full_name || !role_id)
      return res.status(400).json({ error: 'username, password, full_name, role_id обязательны' });
    const ex = await db('SELECT id FROM users WHERE username=$1', [username]);
    if (ex.rows.length) return res.status(400).json({ error: 'Пользователь уже существует' });
    const hash = await bcrypt.hash(password, 12);
    const r = await db(
      `INSERT INTO users (username, password_hash, full_name, email, phone, role_id, organization_id, enterprise_id, res_unit_id, spbipk_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id, username, full_name`,
      [username, hash, full_name, email, phone, role_id, organization_id, enterprise_id, res_unit_id, spbipk_id || null]);
    res.status(201).json(r.rows[0]);
  } catch (err) { console.error(err); res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.get('/api/auth/me', auth, (req, res) => {
  const u = req.user;
  res.json({ id: u.id, username: u.username, full_name: u.full_name, email: u.email, phone: u.phone,
    role_name: u.role_name, role_display_name: u.role_display_name, role_level: u.role_level,
    general_permissions: u.general_permissions, organization_id: u.organization_id,
    enterprise_id: u.enterprise_id, res_unit_id: u.res_unit_id, spbipk_id: u.spbipk_id });
});

app.get('/api/auth/roles', auth, async (req, res) => {
  try {
    const r = await db('SELECT id, name, display_name, level, description, general_permissions FROM roles ORDER BY name');
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
app.post('/api/org/organizations', auth, perm('can_create'), levelCheck(['ia']), async (req, res) => {
  try { res.status(201).json(await orgCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/org/organizations/:id', auth, perm('can_edit'), levelCheck(['ia']), async (req, res) => {
  try { res.json(await orgCRUD.update(req.params.id, req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/org/enterprises', auth, async (req, res) => {
  try {
    let sql = 'SELECT e.*, o.name as organization_name FROM enterprises e LEFT JOIN organizations o ON e.organization_id=o.id WHERE e.is_active=true';
    const p = [];
    if (['enterprise', 'spbipk', 'res'].includes(req.user.role_level)) {
      p.push(req.user.enterprise_id); sql += ` AND e.id=$${p.length}`;
    }
    sql += ' ORDER BY e.name';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/org/enterprises', auth, perm('can_create'), levelCheck(['ia']), async (req, res) => {
  try { res.status(201).json(await entCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/org/enterprises/:id', auth, perm('can_edit'), levelCheck(['ia']), async (req, res) => {
  try { res.json(await entCRUD.update(req.params.id, req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// --- СПБиПК ---
app.get('/api/org/spbipk', auth, async (req, res) => {
  try {
    let sql = `SELECT s.*, e.name as enterprise_name FROM spbipk s LEFT JOIN enterprises e ON s.enterprise_id=e.id WHERE s.is_active=true`;
    const p = [];
    if (['enterprise', 'spbipk'].includes(req.user.role_level)) {
      p.push(req.user.enterprise_id); sql += ` AND s.enterprise_id=$${p.length}`;
    } else if (req.user.role_level === 'res') {
      // РЭС видит только СПБиПК своего предприятия (для справки)
      p.push(req.user.enterprise_id); sql += ` AND s.enterprise_id=$${p.length}`;
    }
    if (req.query.enterprise_id) { p.push(req.query.enterprise_id); sql += ` AND s.enterprise_id=$${p.length}`; }
    sql += ' ORDER BY s.name';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/org/spbipk', auth, perm('can_create'), levelCheck(['ia']), async (req, res) => {
  try { res.status(201).json(await spbipkCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/org/spbipk/:id', auth, perm('can_edit'), levelCheck(['ia', 'spbipk']), async (req, res) => {
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
    if (['enterprise', 'spbipk'].includes(req.user.role_level)) {
      p.push(req.user.enterprise_id); sql += ` AND r.enterprise_id=$${p.length}`;
    } else if (req.user.role_level === 'res') {
      p.push(req.user.res_unit_id); sql += ` AND r.id=$${p.length}`;
    }
    if (req.query.enterprise_id) { p.push(req.query.enterprise_id); sql += ` AND r.enterprise_id=$${p.length}`; }
    if (req.query.spbipk_id) { p.push(req.query.spbipk_id); sql += ` AND r.spbipk_id=$${p.length}`; }
    sql += ' ORDER BY r.name';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/org/res-units', auth, perm('can_create'), levelCheck(['ia', 'spbipk']), async (req, res) => {
  try { res.status(201).json(await resCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/org/res-units/:id', auth, perm('can_edit'), levelCheck(['ia', 'spbipk']), async (req, res) => {
  try { res.json(await resCRUD.update(req.params.id, req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// --- Подразделения ---
app.get('/api/org/departments', auth, async (req, res) => {
  try {
    let sql = `SELECT d.*, r.name as res_name FROM departments d LEFT JOIN res_units r ON d.res_unit_id=r.id WHERE d.is_active=true`;
    const p = [];
    if (req.user.role_level === 'res') {
      p.push(req.user.res_unit_id); sql += ` AND d.res_unit_id=$${p.length}`;
    }
    if (req.query.res_unit_id) { p.push(req.query.res_unit_id); sql += ` AND d.res_unit_id=$${p.length}`; }
    sql += ' ORDER BY d.name';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/org/departments', auth, perm('can_create'), levelCheck(['ia', 'spbipk', 'res']), async (req, res) => {
  try { res.status(201).json(await deptCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/org/departments/:id', auth, perm('can_edit'), levelCheck(['ia', 'spbipk']), async (req, res) => {
  try { res.json(await deptCRUD.update(req.params.id, req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// --- Org Tree ---
app.get('/api/org/tree', auth, async (req, res) => {
  try {
    const orgs = (await db('SELECT * FROM organizations WHERE is_active=true')).rows;
    const level = req.user.role_level;

    let entSql = 'SELECT * FROM enterprises WHERE is_active=true';
    let spSql = 'SELECT * FROM spbipk WHERE is_active=true';
    let resSql = 'SELECT * FROM res_units WHERE is_active=true';
    let deptSql = 'SELECT * FROM departments WHERE is_active=true';
    let whSql = 'SELECT * FROM warehouses WHERE is_active=true';

    const entP = []; const spP = []; const resP = []; const whP = [];

    if (['enterprise', 'spbipk', 'res'].includes(level) && req.user.enterprise_id) {
      entP.push(req.user.enterprise_id);
      entSql += ` AND id=$1`;
      spP.push(req.user.enterprise_id);
      spSql += ` AND enterprise_id=$1`;
    }
    if (['enterprise', 'spbipk'].includes(level) && req.user.enterprise_id) {
      resP.push(req.user.enterprise_id);
      resSql += ` AND enterprise_id=$1`;
    } else if (level === 'res' && req.user.res_unit_id) {
      resP.push(req.user.res_unit_id);
      resSql += ` AND id=$1`;
    }

    const ents = (await db(entSql, entP)).rows;
    const sps = (await db(spSql, spP)).rows;
    const units = (await db(resSql, resP)).rows;
    const depts = (await db(deptSql)).rows;
    const whs = (await db(whSql)).rows;

    res.json(orgs.map(o => ({
      ...o,
      warehouses: whs.filter(w => w.warehouse_type === 'ia' && !w.enterprise_id),
      enterprises: ents.filter(e => e.organization_id === o.id).map(e => ({
        ...e,
        spbipk_list: sps.filter(s => s.enterprise_id === e.id).map(sp => ({
          ...sp,
          warehouses: whs.filter(w => w.spbipk_id === sp.id)
        })),
        res_units: units.filter(r => r.enterprise_id === e.id).map(r => ({
          ...r,
          warehouses: whs.filter(w => w.res_unit_id === r.id),
          departments: depts.filter(d => d.res_unit_id === r.id)
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
app.post('/api/siz/categories', auth, perm('can_create'), levelCheck(['ia', 'spbipk']), async (req, res) => {
  try { res.status(201).json(await catCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/siz/categories/:id', auth, perm('can_edit'), levelCheck(['ia', 'spbipk']), async (req, res) => {
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
app.post('/api/siz/items', auth, perm('can_create'), levelCheck(['ia', 'spbipk']), async (req, res) => {
  try { res.status(201).json(await itemCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/siz/items/:id', auth, perm('can_edit'), levelCheck(['ia', 'spbipk']), async (req, res) => {
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
    let sql = `SELECT p.*,
      ent.name as enterprise_name,
      r.name as res_name, d.name as department_name,
      (SELECT COUNT(*) FROM position_siz_norms n WHERE n.position_id=p.id AND n.is_active=true) as norms_count,
      (SELECT COUNT(*) FROM employees e WHERE e.position_id=p.id AND e.is_active=true) as employees_count
      FROM positions p
      LEFT JOIN enterprises ent ON p.enterprise_id=ent.id
      LEFT JOIN res_units r ON p.res_unit_id=r.id
      LEFT JOIN departments d ON p.department_id=d.id
      WHERE p.is_active=true`;
    const params = [];
    if (['enterprise', 'spbipk'].includes(req.user.role_level)) {
      params.push(req.user.enterprise_id); sql += ` AND p.enterprise_id=$${params.length}`;
    } else if (req.user.role_level === 'res') {
      params.push(req.user.res_unit_id); sql += ` AND p.res_unit_id=$${params.length}`;
    }
    if (req.query.enterprise_id) { params.push(req.query.enterprise_id); sql += ` AND p.enterprise_id=$${params.length}`; }
    if (req.query.res_unit_id) { params.push(req.query.res_unit_id); sql += ` AND p.res_unit_id=$${params.length}`; }
    sql += ' ORDER BY p.name';
    res.json((await db(sql, params)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/positions', auth, perm('can_create'), levelCheck(['ia', 'spbipk']), async (req, res) => {
  try { res.status(201).json(await posCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/positions/:id', auth, perm('can_edit'), levelCheck(['ia', 'spbipk']), async (req, res) => {
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
app.post('/api/positions/:id/norms', auth, perm('can_create'), levelCheck(['ia', 'spbipk']), async (req, res) => {
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

// ============ ROUTES: TON ============

app.get('/api/ton', auth, async (req, res) => {
  try {
    let sql = `SELECT n.id, n.position_id, n.siz_item_id, n.quantity, n.issue_period_months,
      p.name as position_name, p.code as position_code, p.enterprise_id, p.res_unit_id, p.department_id,
      i.name as item_name, i.code as item_code, i.unit, i.wear_period_months, i.exploitation_months, i.exploitation_years,
      c.name as category_name
      FROM position_siz_norms n
      JOIN positions p ON n.position_id = p.id AND p.is_active = true
      JOIN siz_items i ON n.siz_item_id = i.id AND i.is_active = true
      LEFT JOIN siz_categories c ON i.category_id = c.id
      WHERE n.is_active = true`;
    const params = [];
    if (req.query.position_id) { params.push(req.query.position_id); sql += ` AND n.position_id = $${params.length}`; }
    if (req.query.category_id) { params.push(req.query.category_id); sql += ` AND i.category_id = $${params.length}`; }
    sql += ' ORDER BY p.name, c.name, i.name';
    res.json((await db(sql, params)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/ton/:id', auth, perm('can_delete'), levelCheck(['ia', 'spbipk']), async (req, res) => {
  try {
    const r = await db('UPDATE position_siz_norms SET is_active = false WHERE id = $1 RETURNING *', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Норма не найдена' });
    await audit(req.user.id, 'position_siz_norms', req.params.id, 'delete', {}, req.ip);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ton/items-for-employee/:employeeId', auth, async (req, res) => {
  try {
    const sql = `SELECT i.id, i.name, i.code, i.unit, i.wear_period_months,
      c.name as category_name, n.quantity as norm_quantity, n.issue_period_months
      FROM position_siz_norms n
      JOIN siz_items i ON n.siz_item_id = i.id AND i.is_active = true
      LEFT JOIN siz_categories c ON i.category_id = c.id
      JOIN employees e ON e.position_id = n.position_id AND e.id = $1
      WHERE n.is_active = true ORDER BY c.name, i.name`;
    res.json((await db(sql, [req.params.employeeId])).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ ROUTES: SIZES ============

app.get('/api/sizes', auth, async (req, res) => {
  try {
    let sql = 'SELECT * FROM size_references';
    const p = [];
    if (req.query.category_type) { p.push(req.query.category_type); sql += ` WHERE category_type = $1`; }
    sql += ' ORDER BY category_type, sort_order';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ ROUTES: WAREHOUSES ============

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
    if (req.query.spbipk_id) { p.push(req.query.spbipk_id); sql += ` AND w.spbipk_id = $${p.length}`; }
    if (req.query.res_unit_id) { p.push(req.query.res_unit_id); sql += ` AND w.res_unit_id = $${p.length}`; }
    // Visibility by role
    if (req.user.role_level === 'enterprise') {
      p.push(req.user.enterprise_id); sql += ` AND w.enterprise_id = $${p.length}`;
    } else if (req.user.role_level === 'spbipk') {
      p.push(req.user.enterprise_id); sql += ` AND w.enterprise_id = $${p.length}`;
    } else if (req.user.role_level === 'res') {
      p.push(req.user.res_unit_id); sql += ` AND w.res_unit_id = $${p.length}`;
    }
    sql += ' ORDER BY w.warehouse_type, w.name';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

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

app.get('/api/warehouses/:id/stock', auth, async (req, res) => {
  try {
    const sql = `SELECT ws.id, ws.siz_item_id, ws.size_value, ws.quantity,
      i.name as item_name, i.code as item_code, i.unit, i.gender as item_gender, i.season,
      i.exploitation_months, i.exploitation_years, c.name as category_name, c.code as category_code
      FROM warehouse_stock ws
      JOIN siz_items i ON ws.siz_item_id = i.id
      LEFT JOIN siz_categories c ON i.category_id = c.id
      WHERE ws.warehouse_id = $1 AND ws.quantity > 0
      ORDER BY c.name, i.name, i.gender, ws.size_value`;
    res.json((await db(sql, [req.params.id])).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Приход
app.post('/api/warehouses/:id/receipt', auth, perm('can_create'), async (req, res) => {
  try {
    const { siz_item_id, size_value, quantity, document_reference, notes, movement_date } = req.body;
    if (!siz_item_id || !quantity || quantity < 1)
      return res.status(400).json({ error: 'siz_item_id и quantity обязательны' });
    const sv = size_value || '';
    await db(`INSERT INTO warehouse_stock (warehouse_id, siz_item_id, size_value, quantity)
      VALUES ($1,$2,$3,$4) ON CONFLICT (warehouse_id, siz_item_id, size_value)
      DO UPDATE SET quantity = warehouse_stock.quantity + $4`,
      [req.params.id, siz_item_id, sv, quantity]);
    const r = await db(`INSERT INTO stock_movements
      (movement_type, siz_item_id, size_value, quantity, to_warehouse_id, document_reference, notes, moved_by, movement_date)
      VALUES ('receipt',$1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [siz_item_id, sv, quantity, req.params.id, document_reference||null, notes||null, req.user.id,
       movement_date || new Date().toISOString().split('T')[0]]);
    await audit(req.user.id, 'stock_movements', r.rows[0].id, 'create', req.body, req.ip);
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Перемещение
app.post('/api/warehouses/transfer', auth, perm('can_create'), async (req, res) => {
  try {
    const { from_warehouse_id, to_warehouse_id, siz_item_id, size_value, quantity, document_reference, notes, movement_date } = req.body;
    if (!from_warehouse_id || !to_warehouse_id || !siz_item_id || !quantity)
      return res.status(400).json({ error: 'Все поля обязательны' });
    const sv = size_value || '';
    const stock = await db('SELECT quantity FROM warehouse_stock WHERE warehouse_id=$1 AND siz_item_id=$2 AND size_value=$3',
      [from_warehouse_id, siz_item_id, sv]);
    const available = stock.rows[0]?.quantity || 0;
    if (available < quantity) return res.status(400).json({ error: `Недостаточно на складе (есть: ${available})` });
    await db('UPDATE warehouse_stock SET quantity = quantity - $1 WHERE warehouse_id=$2 AND siz_item_id=$3 AND size_value=$4',
      [quantity, from_warehouse_id, siz_item_id, sv]);
    await db(`INSERT INTO warehouse_stock (warehouse_id, siz_item_id, size_value, quantity)
      VALUES ($1,$2,$3,$4) ON CONFLICT (warehouse_id, siz_item_id, size_value)
      DO UPDATE SET quantity = warehouse_stock.quantity + $4`,
      [to_warehouse_id, siz_item_id, sv, quantity]);
    const r = await db(`INSERT INTO stock_movements
      (movement_type, siz_item_id, size_value, quantity, from_warehouse_id, to_warehouse_id, document_reference, notes, moved_by, movement_date)
      VALUES ('transfer',$1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [siz_item_id, sv, quantity, from_warehouse_id, to_warehouse_id, document_reference||null, notes||null, req.user.id,
       movement_date || new Date().toISOString().split('T')[0]]);
    await audit(req.user.id, 'stock_movements', r.rows[0].id, 'create', req.body, req.ip);
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Выдача
app.post('/api/warehouses/:id/issue', auth, perm('can_create'), async (req, res) => {
  try {
    const { employee_id, siz_item_id, size_value, quantity, document_reference, notes, movement_date } = req.body;
    if (!employee_id || !siz_item_id || !quantity)
      return res.status(400).json({ error: 'employee_id, siz_item_id, quantity обязательны' });
    const sv = size_value || '';
    const md = movement_date || new Date().toISOString().split('T')[0];
    const stock = await db('SELECT quantity FROM warehouse_stock WHERE warehouse_id=$1 AND siz_item_id=$2 AND size_value=$3',
      [req.params.id, siz_item_id, sv]);
    const available = stock.rows[0]?.quantity || 0;
    if (available < quantity) return res.status(400).json({ error: `Недостаточно на складе (есть: ${available})` });
    await db('UPDATE warehouse_stock SET quantity = quantity - $1 WHERE warehouse_id=$2 AND siz_item_id=$3 AND size_value=$4',
      [quantity, req.params.id, siz_item_id, sv]);
    const itemR = await db('SELECT exploitation_years FROM siz_items WHERE id=$1', [siz_item_id]);
    const expYears = itemR.rows[0]?.exploitation_years;
    await db(`INSERT INTO employee_siz (employee_id, siz_item_id, size_value, quantity, issued_date, exploitation_start, from_warehouse_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [employee_id, siz_item_id, sv, quantity, md, expYears ? md : null, req.params.id]);
    const r = await db(`INSERT INTO stock_movements
      (movement_type, siz_item_id, size_value, quantity, from_warehouse_id, employee_id, document_reference, notes, moved_by, movement_date)
      VALUES ('issue',$1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [siz_item_id, sv, quantity, req.params.id, employee_id, document_reference||null, notes||null, req.user.id, md]);
    await audit(req.user.id, 'stock_movements', r.rows[0].id, 'create', req.body, req.ip);
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Возврат
app.post('/api/warehouses/:id/return', auth, perm('can_create'), async (req, res) => {
  try {
    const { employee_siz_id, quantity, document_reference, notes, movement_date } = req.body;
    if (!employee_siz_id || !quantity)
      return res.status(400).json({ error: 'employee_siz_id и quantity обязательны' });
    const md = movement_date || new Date().toISOString().split('T')[0];
    const es = await db('SELECT * FROM employee_siz WHERE id=$1 AND status=$2', [employee_siz_id, 'active']);
    if (!es.rows.length) return res.status(404).json({ error: 'Запись не найдена' });
    const rec = es.rows[0];
    if (quantity > rec.quantity) return res.status(400).json({ error: `У сотрудника только ${rec.quantity}` });
    if (quantity >= rec.quantity) {
      await db('UPDATE employee_siz SET status=$1, returned_date=$2 WHERE id=$3', ['returned', md, employee_siz_id]);
    } else {
      await db('UPDATE employee_siz SET quantity = quantity - $1 WHERE id=$2', [quantity, employee_siz_id]);
    }
    await db(`INSERT INTO warehouse_stock (warehouse_id, siz_item_id, size_value, quantity)
      VALUES ($1,$2,$3,$4) ON CONFLICT (warehouse_id, siz_item_id, size_value)
      DO UPDATE SET quantity = warehouse_stock.quantity + $4`,
      [req.params.id, rec.siz_item_id, rec.size_value, quantity]);
    const r = await db(`INSERT INTO stock_movements
      (movement_type, siz_item_id, size_value, quantity, to_warehouse_id, employee_id, document_reference, notes, moved_by, movement_date)
      VALUES ('return',$1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [rec.siz_item_id, rec.size_value, quantity, req.params.id, rec.employee_id,
       document_reference||null, notes||null, req.user.id, md]);
    await audit(req.user.id, 'stock_movements', r.rows[0].id, 'create', req.body, req.ip);
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

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

app.get('/api/employee-siz/:employeeId', auth, async (req, res) => {
  try {
    const sql = `SELECT es.*, i.name as item_name, i.unit, i.exploitation_months, i.exploitation_years,
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

// ============ ROUTES: SIZ CARDS ============

// Get all SIZ cards with filters
app.get('/api/siz-cards', auth, async (req, res) => {
  try {
    let sql = `SELECT sc.*, i.name as item_name, i.code as item_code, i.unit, i.exploitation_months, i.exploitation_years,
      i.gender as item_gender, i.season, c.name as category_name, c.code as category_code,
      w.name as warehouse_name, w.warehouse_type,
      e.last_name, e.first_name, e.middle_name, e.employee_number,
      ent.name as enterprise_name, r.name as res_name, d.name as department_name
      FROM siz_cards sc
      JOIN siz_items i ON sc.siz_item_id = i.id
      LEFT JOIN siz_categories c ON i.category_id = c.id
      LEFT JOIN warehouses w ON sc.warehouse_id = w.id
      LEFT JOIN employees e ON sc.employee_id = e.id
      LEFT JOIN enterprises ent ON sc.enterprise_id = ent.id
      LEFT JOIN res_units r ON sc.res_unit_id = r.id
      LEFT JOIN departments d ON sc.department_id = d.id
      WHERE sc.is_active = true`;
    const p = [];
    // Role-based filtering
    if (['enterprise', 'spbipk'].includes(req.user.role_level)) {
      p.push(req.user.enterprise_id); sql += ` AND sc.enterprise_id=$${p.length}`;
    } else if (req.user.role_level === 'res') {
      p.push(req.user.res_unit_id); sql += ` AND sc.res_unit_id=$${p.length}`;
    }
    // Query filters
    if (req.query.status) { p.push(req.query.status); sql += ` AND sc.status=$${p.length}`; }
    if (req.query.location_type) { p.push(req.query.location_type); sql += ` AND sc.location_type=$${p.length}`; }
    if (req.query.employee_id) { p.push(req.query.employee_id); sql += ` AND sc.employee_id=$${p.length}`; }
    if (req.query.warehouse_id) { p.push(req.query.warehouse_id); sql += ` AND sc.warehouse_id=$${p.length}`; }
    if (req.query.enterprise_id) { p.push(req.query.enterprise_id); sql += ` AND sc.enterprise_id=$${p.length}`; }
    if (req.query.res_unit_id) { p.push(req.query.res_unit_id); sql += ` AND sc.res_unit_id=$${p.length}`; }
    if (req.query.siz_item_id) { p.push(req.query.siz_item_id); sql += ` AND sc.siz_item_id=$${p.length}`; }
    if (req.query.expired === 'true') { sql += ` AND sc.exploitation_end < CURRENT_DATE AND sc.status = 'issued'`; }
    if (req.query.search) {
      p.push(`%${req.query.search}%`);
      sql += ` AND (sc.card_number ILIKE $${p.length} OR i.name ILIKE $${p.length} OR e.last_name ILIKE $${p.length})`;
    }
    sql += ' ORDER BY sc.created_at DESC';
    if (req.query.limit) { p.push(parseInt(req.query.limit)); sql += ` LIMIT $${p.length}`; }
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get SIZ cards for employee (for employee card page) — must be before :id route
app.get('/api/siz-cards/by-employee/:employeeId', auth, async (req, res) => {
  try {
    const sql = `SELECT sc.*, i.name as item_name, i.code as item_code, i.unit, i.exploitation_months, i.exploitation_years,
      c.name as category_name, w.name as warehouse_name
      FROM siz_cards sc
      JOIN siz_items i ON sc.siz_item_id = i.id
      LEFT JOIN siz_categories c ON i.category_id = c.id
      LEFT JOIN warehouses w ON sc.warehouse_id = w.id
      WHERE sc.employee_id = $1 AND sc.status IN ('issued','expired') AND sc.is_active = true
      ORDER BY c.name, i.name`;
    res.json((await db(sql, [req.params.employeeId])).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get single SIZ card
app.get('/api/siz-cards/:id', auth, async (req, res) => {
  try {
    const sql = `SELECT sc.*, i.name as item_name, i.code as item_code, i.unit, i.exploitation_months, i.exploitation_years,
      i.gender as item_gender, i.season, c.name as category_name,
      w.name as warehouse_name, w.warehouse_type,
      e.last_name, e.first_name, e.middle_name, e.employee_number,
      ent.name as enterprise_name, r.name as res_name, d.name as department_name,
      p.name as position_name
      FROM siz_cards sc
      JOIN siz_items i ON sc.siz_item_id = i.id
      LEFT JOIN siz_categories c ON i.category_id = c.id
      LEFT JOIN warehouses w ON sc.warehouse_id = w.id
      LEFT JOIN employees e ON sc.employee_id = e.id
      LEFT JOIN positions p ON e.position_id = p.id
      LEFT JOIN enterprises ent ON sc.enterprise_id = ent.id
      LEFT JOIN res_units r ON sc.res_unit_id = r.id
      LEFT JOIN departments d ON sc.department_id = d.id
      WHERE sc.id = $1`;
    const result = await db(sql, [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Карточка не найдена' });
    res.json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get SIZ card movement history
app.get('/api/siz-cards/:id/movements', auth, async (req, res) => {
  try {
    const sql = `SELECT m.*,
      fw.name as from_warehouse_name, tw.name as to_warehouse_name,
      fe.last_name as from_employee_last, fe.first_name as from_employee_first,
      te.last_name as to_employee_last, te.first_name as to_employee_first,
      u.full_name as moved_by_name
      FROM siz_card_movements m
      LEFT JOIN warehouses fw ON m.from_warehouse_id = fw.id
      LEFT JOIN warehouses tw ON m.to_warehouse_id = tw.id
      LEFT JOIN employees fe ON m.from_employee_id = fe.id
      LEFT JOIN employees te ON m.to_employee_id = te.id
      LEFT JOIN users u ON m.moved_by = u.id
      WHERE m.siz_card_id = $1
      ORDER BY m.movement_date DESC, m.created_at DESC`;
    res.json((await db(sql, [req.params.id])).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Create SIZ card (поступление на склад)
app.post('/api/siz-cards', auth, perm('can_create'), async (req, res) => {
  try {
    const { siz_item_id, size_value, warehouse_id, manufacture_date, document_reference, notes, card_number } = req.body;
    if (!siz_item_id || !warehouse_id) return res.status(400).json({ error: 'siz_item_id и warehouse_id обязательны' });

    // Get warehouse info for org structure
    const wh = await db(`SELECT w.*, sp.enterprise_id as sp_ent_id FROM warehouses w
      LEFT JOIN spbipk sp ON w.spbipk_id = sp.id WHERE w.id = $1`, [warehouse_id]);
    if (!wh.rows.length) return res.status(404).json({ error: 'Склад не найден' });
    const warehouse = wh.rows[0];
    const entId = warehouse.enterprise_id || warehouse.sp_ent_id || null;

    // Get exploitation years
    const itemR = await db('SELECT exploitation_years FROM siz_items WHERE id=$1', [siz_item_id]);
    const expYears = itemR.rows[0]?.exploitation_years;

    // Generate card number if not provided
    let cn = card_number;
    if (!cn) {
      const cnt = await db("SELECT COUNT(*) as c FROM siz_cards");
      cn = 'СИЗ-' + String(parseInt(cnt.rows[0].c) + 1).padStart(6, '0');
    }

    const r = await db(`INSERT INTO siz_cards
      (card_number, siz_item_id, size_value, location_type, warehouse_id, enterprise_id, res_unit_id,
       manufacture_date, receipt_date, status, document_reference, notes)
      VALUES ($1,$2,$3,'warehouse',$4,$5,$6,$7,CURRENT_DATE,'in_stock',$8,$9) RETURNING *`,
      [cn, siz_item_id, size_value || '', warehouse_id, entId, warehouse.res_unit_id || null,
       manufacture_date || null, document_reference || null, notes || null]);

    // Log movement
    await db(`INSERT INTO siz_card_movements (siz_card_id, movement_type, to_warehouse_id, moved_by, movement_date, document_reference, notes)
      VALUES ($1,'receipt',$2,$3,CURRENT_DATE,$4,$5)`,
      [r.rows[0].id, warehouse_id, req.user.id, document_reference || null, notes || null]);

    // Also update warehouse_stock for compatibility
    await db(`INSERT INTO warehouse_stock (warehouse_id, siz_item_id, size_value, quantity)
      VALUES ($1,$2,$3,1) ON CONFLICT (warehouse_id, siz_item_id, size_value)
      DO UPDATE SET quantity = warehouse_stock.quantity + 1`,
      [warehouse_id, siz_item_id, size_value || '']);

    await audit(req.user.id, 'siz_cards', r.rows[0].id, 'create', req.body, req.ip);
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Batch create SIZ cards
app.post('/api/siz-cards/batch', auth, perm('can_create'), async (req, res) => {
  try {
    const { siz_item_id, size_value, warehouse_id, quantity, manufacture_date, document_reference, notes } = req.body;
    if (!siz_item_id || !warehouse_id || !quantity || quantity < 1) return res.status(400).json({ error: 'siz_item_id, warehouse_id, quantity обязательны' });

    const wh = await db(`SELECT w.*, sp.enterprise_id as sp_ent_id FROM warehouses w
      LEFT JOIN spbipk sp ON w.spbipk_id = sp.id WHERE w.id = $1`, [warehouse_id]);
    if (!wh.rows.length) return res.status(404).json({ error: 'Склад не найден' });
    const warehouse = wh.rows[0];
    const entId = warehouse.enterprise_id || warehouse.sp_ent_id || null;

    const cnt = await db("SELECT COUNT(*) as c FROM siz_cards");
    let num = parseInt(cnt.rows[0].c) + 1;
    const created = [];

    for (let q = 0; q < quantity; q++) {
      const cn = 'СИЗ-' + String(num++).padStart(6, '0');
      const r = await db(`INSERT INTO siz_cards
        (card_number, siz_item_id, size_value, location_type, warehouse_id, enterprise_id, res_unit_id,
         manufacture_date, receipt_date, status, document_reference, notes)
        VALUES ($1,$2,$3,'warehouse',$4,$5,$6,$7,CURRENT_DATE,'in_stock',$8,$9) RETURNING *`,
        [cn, siz_item_id, size_value || '', warehouse_id, entId, warehouse.res_unit_id || null,
         manufacture_date || null, document_reference || null, notes || null]);
      await db(`INSERT INTO siz_card_movements (siz_card_id, movement_type, to_warehouse_id, moved_by, movement_date, document_reference)
        VALUES ($1,'receipt',$2,$3,CURRENT_DATE,$4)`,
        [r.rows[0].id, warehouse_id, req.user.id, document_reference || null]);
      created.push(r.rows[0]);
    }

    // Update warehouse stock
    await db(`INSERT INTO warehouse_stock (warehouse_id, siz_item_id, size_value, quantity)
      VALUES ($1,$2,$3,$4) ON CONFLICT (warehouse_id, siz_item_id, size_value)
      DO UPDATE SET quantity = warehouse_stock.quantity + $4`,
      [warehouse_id, siz_item_id, size_value || '', quantity]);

    await audit(req.user.id, 'siz_cards', null, 'batch_create', { count: quantity }, req.ip);
    res.status(201).json({ created: created.length, cards: created });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Batch issue — выдать несколько одинаковых СИЗ одному сотруднику с последовательными таймерами
app.post('/api/siz-cards/batch-issue', auth, perm('can_create'), async (req, res) => {
  try {
    const { employee_id, siz_item_id, warehouse_id, quantity, document_reference, notes, movement_date } = req.body;
    if (!employee_id || !siz_item_id || !warehouse_id || !quantity) {
      return res.status(400).json({ error: 'employee_id, siz_item_id, warehouse_id, quantity обязательны' });
    }

    const emp = (await db('SELECT * FROM employees WHERE id=$1', [employee_id])).rows[0];
    if (!emp) return res.status(404).json({ error: 'Сотрудник не найден' });

    const itemR = await db('SELECT exploitation_months, exploitation_years, name FROM siz_items WHERE id=$1', [siz_item_id]);
    const item = itemR.rows[0];
    if (!item) return res.status(404).json({ error: 'СИЗ не найдено' });
    const expMonths = item.exploitation_months;

    // Find available cards on the warehouse
    const available = (await db(
      `SELECT id, warehouse_id FROM siz_cards WHERE siz_item_id=$1 AND warehouse_id=$2 AND status='in_stock' AND is_active=true ORDER BY created_at ASC LIMIT $3`,
      [siz_item_id, warehouse_id, quantity]
    )).rows;

    if (available.length < quantity) {
      return res.status(400).json({ error: `На складе только ${available.length} шт., запрошено ${quantity}` });
    }

    const md = movement_date || new Date().toISOString().split('T')[0];

    // Find the latest exploitation_end for this item+employee (to chain sequentially)
    const lastCard = (await db(
      `SELECT exploitation_end FROM siz_cards WHERE employee_id=$1 AND siz_item_id=$2 AND status='issued' AND exploitation_end IS NOT NULL ORDER BY exploitation_end DESC LIMIT 1`,
      [employee_id, siz_item_id]
    )).rows[0];

    let currentStart = new Date(md);
    if (lastCard?.exploitation_end && new Date(lastCard.exploitation_end) > currentStart) {
      currentStart = new Date(lastCard.exploitation_end);
    }

    const issued = [];
    for (let i = 0; i < available.length; i++) {
      const cardId = available[i].id;
      let startStr = currentStart.toISOString().split('T')[0];
      let expEnd = null;

      if (expMonths) {
        const endDate = new Date(currentStart);
        endDate.setMonth(endDate.getMonth() + expMonths);
        expEnd = endDate.toISOString().split('T')[0];
        currentStart = endDate; // Next card starts when this one ends
      }

      await db(`UPDATE siz_cards SET
        location_type='employee', employee_id=$1, warehouse_id=NULL,
        enterprise_id=$2, res_unit_id=$3, department_id=$4,
        issue_date=$5, exploitation_start=$6, exploitation_end=$7, status='issued'
        WHERE id=$8`,
        [employee_id, emp.enterprise_id, emp.res_unit_id, emp.department_id, md, startStr, expEnd, cardId]);

      await db(`INSERT INTO siz_card_movements (siz_card_id, movement_type, from_warehouse_id, to_employee_id, moved_by, movement_date, document_reference, notes)
        VALUES ($1,'issue',$2,$3,$4,$5,$6,$7)`,
        [cardId, warehouse_id, employee_id, req.user.id, md, document_reference || null, notes || null]);

      issued.push({ id: cardId, exploitation_start: startStr, exploitation_end: expEnd });
    }

    // Update warehouse stock
    await db('UPDATE warehouse_stock SET quantity = GREATEST(quantity - $1, 0) WHERE warehouse_id=$2 AND siz_item_id=$3',
      [available.length, warehouse_id, siz_item_id]);

    await audit(req.user.id, 'siz_cards', null, 'batch_issue', { employee_id, siz_item_id, count: available.length }, req.ip);
    res.json({ issued: issued.length, cards: issued, message: `Выдано ${issued.length} шт. с последовательными сроками` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Issue SIZ card to employee (выдача)
app.post('/api/siz-cards/:id/issue', auth, perm('can_create'), async (req, res) => {
  try {
    const { employee_id, document_reference, notes, movement_date } = req.body;
    if (!employee_id) return res.status(400).json({ error: 'employee_id обязателен' });

    const card = (await db('SELECT * FROM siz_cards WHERE id=$1 AND is_active=true', [req.params.id])).rows[0];
    if (!card) return res.status(404).json({ error: 'Карточка не найдена' });
    if (card.status !== 'in_stock') return res.status(400).json({ error: `Нельзя выдать карточку в статусе: ${card.status}` });

    const emp = (await db('SELECT * FROM employees WHERE id=$1', [employee_id])).rows[0];
    if (!emp) return res.status(404).json({ error: 'Сотрудник не найден' });

    const itemR = await db('SELECT exploitation_months, exploitation_years FROM siz_items WHERE id=$1', [card.siz_item_id]);
    const expMonths = itemR.rows[0]?.exploitation_months;
    const md = movement_date || new Date().toISOString().split('T')[0];

    // Find the latest exploitation_end for the same item+employee (for sequential timing)
    const lastCard = (await db(
      `SELECT exploitation_end FROM siz_cards WHERE employee_id=$1 AND siz_item_id=$2 AND status='issued' AND exploitation_end IS NOT NULL ORDER BY exploitation_end DESC LIMIT 1`,
      [employee_id, card.siz_item_id]
    )).rows[0];

    let startDate = new Date(md);
    if (lastCard?.exploitation_end && new Date(lastCard.exploitation_end) > startDate) {
      startDate = new Date(lastCard.exploitation_end);
    }
    let expEnd = null;
    if (expMonths) {
      const endDate = new Date(startDate);
      endDate.setMonth(endDate.getMonth() + expMonths);
      expEnd = endDate.toISOString().split('T')[0];
    }
    const startStr = startDate.toISOString().split('T')[0];

    await db(`UPDATE siz_cards SET
      location_type='employee', employee_id=$1, warehouse_id=NULL,
      enterprise_id=$2, res_unit_id=$3, department_id=$4,
      issue_date=$5, exploitation_start=$6, exploitation_end=$7, status='issued'
      WHERE id=$8`,
      [employee_id, emp.enterprise_id, emp.res_unit_id, emp.department_id, md, startStr, expEnd, req.params.id]);

    await db(`INSERT INTO siz_card_movements (siz_card_id, movement_type, from_warehouse_id, to_employee_id, moved_by, movement_date, document_reference, notes)
      VALUES ($1,'issue',$2,$3,$4,$5,$6,$7)`,
      [req.params.id, card.warehouse_id, employee_id, req.user.id, md, document_reference || null, notes || null]);

    if (card.warehouse_id) {
      await db('UPDATE warehouse_stock SET quantity = GREATEST(quantity - 1, 0) WHERE warehouse_id=$1 AND siz_item_id=$2 AND size_value=$3',
        [card.warehouse_id, card.siz_item_id, card.size_value]);
    }

    await db(`INSERT INTO employee_siz (employee_id, siz_item_id, size_value, quantity, issued_date, exploitation_start, from_warehouse_id)
      VALUES ($1,$2,$3,1,$4,$5,$6)`,
      [employee_id, card.siz_item_id, card.size_value, md, expMonths ? startStr : null, card.warehouse_id]);

    await audit(req.user.id, 'siz_cards', req.params.id, 'issue', { employee_id }, req.ip);
    const updated = (await db('SELECT * FROM siz_cards WHERE id=$1', [req.params.id])).rows[0];
    res.json(updated);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Return SIZ card from employee (возврат)
app.post('/api/siz-cards/:id/return', auth, perm('can_create'), async (req, res) => {
  try {
    const { warehouse_id, document_reference, notes, movement_date } = req.body;
    if (!warehouse_id) return res.status(400).json({ error: 'warehouse_id обязателен' });

    const card = (await db('SELECT * FROM siz_cards WHERE id=$1 AND is_active=true', [req.params.id])).rows[0];
    if (!card) return res.status(404).json({ error: 'Карточка не найдена' });
    if (card.status !== 'issued' && card.status !== 'expired') return res.status(400).json({ error: `Нельзя вернуть карточку в статусе: ${card.status}` });

    const wh = await db(`SELECT w.*, sp.enterprise_id as sp_ent_id FROM warehouses w
      LEFT JOIN spbipk sp ON w.spbipk_id = sp.id WHERE w.id = $1`, [warehouse_id]);
    const warehouse = wh.rows[0];
    const entId = warehouse?.enterprise_id || warehouse?.sp_ent_id || null;
    const md = movement_date || new Date().toISOString().split('T')[0];

    await db(`UPDATE siz_cards SET
      location_type='warehouse', warehouse_id=$1, employee_id=NULL,
      enterprise_id=$2, res_unit_id=$3, department_id=NULL,
      status='in_stock', issue_date=NULL, exploitation_start=NULL, exploitation_end=NULL
      WHERE id=$4`,
      [warehouse_id, entId, warehouse?.res_unit_id || null, req.params.id]);

    await db(`INSERT INTO siz_card_movements (siz_card_id, movement_type, from_employee_id, to_warehouse_id, moved_by, movement_date, document_reference, notes)
      VALUES ($1,'return',$2,$3,$4,$5,$6,$7)`,
      [req.params.id, card.employee_id, warehouse_id, req.user.id, md, document_reference || null, notes || null]);

    // Increase warehouse stock
    await db(`INSERT INTO warehouse_stock (warehouse_id, siz_item_id, size_value, quantity)
      VALUES ($1,$2,$3,1) ON CONFLICT (warehouse_id, siz_item_id, size_value)
      DO UPDATE SET quantity = warehouse_stock.quantity + 1`,
      [warehouse_id, card.siz_item_id, card.size_value]);

    await audit(req.user.id, 'siz_cards', req.params.id, 'return', { warehouse_id }, req.ip);
    const updated = (await db('SELECT * FROM siz_cards WHERE id=$1', [req.params.id])).rows[0];
    res.json(updated);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Transfer SIZ card between warehouses
app.post('/api/siz-cards/:id/transfer', auth, perm('can_create'), async (req, res) => {
  try {
    const { to_warehouse_id, document_reference, notes, movement_date } = req.body;
    if (!to_warehouse_id) return res.status(400).json({ error: 'to_warehouse_id обязателен' });

    const card = (await db('SELECT * FROM siz_cards WHERE id=$1 AND is_active=true', [req.params.id])).rows[0];
    if (!card) return res.status(404).json({ error: 'Карточка не найдена' });
    if (card.location_type !== 'warehouse') return res.status(400).json({ error: 'Перемещение возможно только со склада' });

    const wh = await db(`SELECT w.*, sp.enterprise_id as sp_ent_id FROM warehouses w
      LEFT JOIN spbipk sp ON w.spbipk_id = sp.id WHERE w.id = $1`, [to_warehouse_id]);
    const warehouse = wh.rows[0];
    const entId = warehouse?.enterprise_id || warehouse?.sp_ent_id || null;
    const md = movement_date || new Date().toISOString().split('T')[0];

    const fromWhId = card.warehouse_id;
    await db(`UPDATE siz_cards SET warehouse_id=$1, enterprise_id=$2, res_unit_id=$3 WHERE id=$4`,
      [to_warehouse_id, entId, warehouse?.res_unit_id || null, req.params.id]);

    await db(`INSERT INTO siz_card_movements (siz_card_id, movement_type, from_warehouse_id, to_warehouse_id, moved_by, movement_date, document_reference, notes)
      VALUES ($1,'transfer',$2,$3,$4,$5,$6,$7)`,
      [req.params.id, fromWhId, to_warehouse_id, req.user.id, md, document_reference || null, notes || null]);

    // Update warehouse stocks
    if (fromWhId) {
      await db('UPDATE warehouse_stock SET quantity = GREATEST(quantity - 1, 0) WHERE warehouse_id=$1 AND siz_item_id=$2 AND size_value=$3',
        [fromWhId, card.siz_item_id, card.size_value]);
    }
    await db(`INSERT INTO warehouse_stock (warehouse_id, siz_item_id, size_value, quantity)
      VALUES ($1,$2,$3,1) ON CONFLICT (warehouse_id, siz_item_id, size_value)
      DO UPDATE SET quantity = warehouse_stock.quantity + 1`,
      [to_warehouse_id, card.siz_item_id, card.size_value]);

    await audit(req.user.id, 'siz_cards', req.params.id, 'transfer', { from: fromWhId, to: to_warehouse_id }, req.ip);
    const updated = (await db('SELECT * FROM siz_cards WHERE id=$1', [req.params.id])).rows[0];
    res.json(updated);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Write off SIZ card (списание)
app.post('/api/siz-cards/:id/write-off', auth, perm('can_create'), async (req, res) => {
  try {
    const { document_reference, notes, movement_date } = req.body;
    const card = (await db('SELECT * FROM siz_cards WHERE id=$1 AND is_active=true', [req.params.id])).rows[0];
    if (!card) return res.status(404).json({ error: 'Карточка не найдена' });
    const md = movement_date || new Date().toISOString().split('T')[0];

    await db(`UPDATE siz_cards SET location_type='written_off', status='written_off', warehouse_id=NULL, employee_id=NULL WHERE id=$1`, [req.params.id]);

    await db(`INSERT INTO siz_card_movements (siz_card_id, movement_type, from_warehouse_id, from_employee_id, moved_by, movement_date, document_reference, notes)
      VALUES ($1,'write_off',$2,$3,$4,$5,$6,$7)`,
      [req.params.id, card.warehouse_id, card.employee_id, req.user.id, md, document_reference || null, notes || null]);

    await audit(req.user.id, 'siz_cards', req.params.id, 'write_off', {}, req.ip);
    res.json({ message: 'Карточка списана' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Stats for SIZ cards
app.get('/api/siz-cards-stats', auth, async (req, res) => {
  try {
    let where = 'sc.is_active = true';
    const p = [];
    if (['enterprise', 'spbipk'].includes(req.user.role_level)) {
      p.push(req.user.enterprise_id); where += ` AND sc.enterprise_id=$${p.length}`;
    } else if (req.user.role_level === 'res') {
      p.push(req.user.res_unit_id); where += ` AND sc.res_unit_id=$${p.length}`;
    }
    const total = (await db(`SELECT COUNT(*) as c FROM siz_cards sc WHERE ${where}`, p)).rows[0].c;
    const issued = (await db(`SELECT COUNT(*) as c FROM siz_cards sc WHERE ${where} AND sc.status='issued'`, p)).rows[0].c;
    const inStock = (await db(`SELECT COUNT(*) as c FROM siz_cards sc WHERE ${where} AND sc.status='in_stock'`, p)).rows[0].c;
    const expired = (await db(`SELECT COUNT(*) as c FROM siz_cards sc WHERE ${where} AND sc.exploitation_end < CURRENT_DATE AND sc.status='issued'`, p)).rows[0].c;
    const writtenOff = (await db(`SELECT COUNT(*) as c FROM siz_cards sc WHERE ${where} AND sc.status='written_off'`, p)).rows[0].c;
    res.json({ total: +total, issued: +issued, in_stock: +inStock, expired: +expired, written_off: +writtenOff });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/warehouses/:id', auth, perm('can_delete'), async (req, res) => {
  try {
    const stock = await db('SELECT SUM(quantity) as total FROM warehouse_stock WHERE warehouse_id=$1', [req.params.id]);
    if (parseInt(stock.rows[0]?.total || 0) > 0)
      return res.status(400).json({ error: 'Нельзя удалить склад с остатками' });
    const r = await db('UPDATE warehouses SET is_active=false WHERE id=$1 RETURNING *', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Склад не найден' });
    await audit(req.user.id, 'warehouses', req.params.id, 'delete', {}, req.ip);
    res.json({ message: 'Склад удалён' });
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
    if (['enterprise', 'spbipk'].includes(req.user.role_level)) {
      p.push(req.user.enterprise_id); sql += ` AND e.enterprise_id=$${p.length}`;
    } else if (req.user.role_level === 'res') {
      p.push(req.user.res_unit_id); sql += ` AND e.res_unit_id=$${p.length}`;
    }
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
    res.json({ ...emp, norms });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/employees', auth, perm('can_create'), levelCheck(['ia', 'spbipk']), async (req, res) => {
  try { res.status(201).json(await empCRUD.create(req.body, req.user.id, req.ip)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/employees/:id', auth, perm('can_edit'), levelCheck(['ia', 'spbipk']), async (req, res) => {
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
    if (['enterprise', 'spbipk'].includes(req.user.role_level)) { p.push(req.user.enterprise_id); sql += ` AND e.enterprise_id=$${p.length}`; }
    else if (req.user.role_level === 'res') { p.push(req.user.res_unit_id); sql += ` AND e.res_unit_id=$${p.length}`; }
    if (req.query.employee_id) { p.push(req.query.employee_id); sql += ` AND t.employee_id=$${p.length}`; }
    sql += ' ORDER BY t.transaction_date DESC, t.created_at DESC';
    if (req.query.limit) { p.push(parseInt(req.query.limit)); sql += ` LIMIT $${p.length}`; }
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ ROUTES: ADMIN ============

app.get('/api/admin/users', auth, levelCheck(['ia']), async (req, res) => {
  try {
    res.json((await db(`SELECT u.id, u.username, u.full_name, u.email, u.phone, u.is_active, u.last_login,
      u.role_id, u.organization_id, u.enterprise_id, u.res_unit_id, u.spbipk_id,
      r.display_name as role_name, r.level as role_level,
      o.name as organization_name, e.name as enterprise_name, ru.name as res_name
      FROM users u LEFT JOIN roles r ON u.role_id=r.id LEFT JOIN organizations o ON u.organization_id=o.id
      LEFT JOIN enterprises e ON u.enterprise_id=e.id LEFT JOIN res_units ru ON u.res_unit_id=ru.id
      ORDER BY u.full_name`)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/users/:id', auth, levelCheck(['ia']), async (req, res) => {
  try {
    const { full_name, email, phone, role_id, organization_id, enterprise_id, res_unit_id, spbipk_id, new_password } = req.body;
    const sets = []; const vals = []; let i = 1;
    if (full_name !== undefined) { sets.push(`full_name=$${i}`); vals.push(full_name); i++; }
    if (email !== undefined) { sets.push(`email=$${i}`); vals.push(email); i++; }
    if (phone !== undefined) { sets.push(`phone=$${i}`); vals.push(phone); i++; }
    if (role_id !== undefined) { sets.push(`role_id=$${i}`); vals.push(role_id); i++; }
    if (organization_id !== undefined) { sets.push(`organization_id=$${i}`); vals.push(organization_id || null); i++; }
    if (enterprise_id !== undefined) { sets.push(`enterprise_id=$${i}`); vals.push(enterprise_id || null); i++; }
    if (res_unit_id !== undefined) { sets.push(`res_unit_id=$${i}`); vals.push(res_unit_id || null); i++; }
    if (spbipk_id !== undefined) { sets.push(`spbipk_id=$${i}`); vals.push(spbipk_id || null); i++; }
    if (new_password) { sets.push(`password_hash=$${i}`); vals.push(await bcrypt.hash(new_password, 12)); i++; }
    if (!sets.length) return res.status(400).json({ error: 'Нет данных' });
    vals.push(req.params.id);
    const r = await db(`UPDATE users SET ${sets.join(',')} WHERE id=$${i} RETURNING id, username, full_name`, vals);
    if (!r.rows.length) return res.status(404).json({ error: 'Пользователь не найден' });
    await audit(req.user.id, 'users', req.params.id, 'update', { full_name, email, role_id }, req.ip);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/users/:id', auth, levelCheck(['ia']), async (req, res) => {
  try {
    const r = await db('UPDATE users SET is_active=false WHERE id=$1 RETURNING id, username', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Пользователь не найден' });
    await audit(req.user.id, 'users', req.params.id, 'delete', {}, req.ip);
    res.json({ message: 'Деактивирован', user: r.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/audit', auth, levelCheck(['ia', 'enterprise']), async (req, res) => {
  try {
    let sql = `SELECT a.*, u.full_name as user_name, u.username FROM audit_log a LEFT JOIN users u ON a.user_id=u.id WHERE 1=1`;
    const p = [];
    if (req.query.table_name) { p.push(req.query.table_name); sql += ` AND a.table_name=$${p.length}`; }
    sql += ' ORDER BY a.created_at DESC LIMIT 100';
    res.json((await db(sql, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ BULK IMPORT ============

app.post('/api/import/employees', auth, perm('can_create'), levelCheck(['ia', 'spbipk']), async (req, res) => {
  try {
    const { rows } = req.body;
    if (!rows?.length) return res.status(400).json({ error: 'Нет данных' });
    let imported = 0;
    for (const r of rows) {
      if (!r.last_name) continue;
      await db(`INSERT INTO employees (last_name, first_name, middle_name, employee_number, enterprise_id, res_unit_id, department_id, position_id, clothing_size, shoe_size)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [r.last_name, r.first_name||null, r.middle_name||null, r.employee_number||null,
         r.enterprise_id||null, r.res_unit_id||null, r.department_id||null, r.position_id||null,
         r.clothing_size||null, r.shoe_size||null]);
      imported++;
    }
    await audit(req.user.id, 'employees', null, 'bulk_import', { count: imported }, req.ip);
    res.json({ imported });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/import/positions', auth, perm('can_create'), levelCheck(['ia', 'spbipk']), async (req, res) => {
  try {
    const { rows } = req.body;
    if (!rows?.length) return res.status(400).json({ error: 'Нет данных' });
    let imported = 0;
    for (const r of rows) {
      if (!r.name) continue;
      await db(`INSERT INTO positions (name, code, enterprise_id, res_unit_id, department_id) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
        [r.name, r.code||null, r.enterprise_id||null, r.res_unit_id||null, r.department_id||null]);
      imported++;
    }
    await audit(req.user.id, 'positions', null, 'bulk_import', { count: imported }, req.ip);
    res.json({ imported });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/import/siz-items', auth, perm('can_create'), levelCheck(['ia', 'spbipk']), async (req, res) => {
  try {
    const { rows } = req.body;
    if (!rows?.length) return res.status(400).json({ error: 'Нет данных' });
    let imported = 0;
    for (const r of rows) {
      if (!r.name) continue;
      const expMonths = r.exploitation_months ? parseInt(r.exploitation_months) : (r.exploitation_years ? Math.round(parseFloat(r.exploitation_years) * 12) : null);
      const expYears = expMonths ? +(expMonths / 12).toFixed(2) : null;
      await db(`INSERT INTO siz_items (name, code, category_id, gender, season, exploitation_months, exploitation_years, unit)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [r.name, r.code||null, r.category_id||null, r.gender||null, r.season||null,
         expMonths, expYears, r.unit||'шт']);
      imported++;
    }
    await audit(req.user.id, 'siz_items', null, 'bulk_import', { count: imported }, req.ip);
    res.json({ imported });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ HEALTH ============
app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

// ============ SPA FALLBACK ============
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ============ DB INIT ============

async function initDB() {
  try {
    // === CORE TABLES ===
    await pool.query(`
      CREATE EXTENSION IF NOT EXISTS "pgcrypto";

      CREATE TABLE IF NOT EXISTS roles (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(50) UNIQUE NOT NULL,
        display_name VARCHAR(100) NOT NULL,
        level VARCHAR(20) NOT NULL,
        description TEXT,
        general_permissions JSONB DEFAULT '{}',
        field_permissions JSONB DEFAULT '{}',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS organizations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        code VARCHAR(50),
        extra JSONB DEFAULT '{}',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS enterprises (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID REFERENCES organizations(id),
        name VARCHAR(255) NOT NULL,
        code VARCHAR(50),
        extra JSONB DEFAULT '{}',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS spbipk (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        enterprise_id UUID REFERENCES enterprises(id),
        name VARCHAR(255) NOT NULL,
        code VARCHAR(50),
        extra JSONB DEFAULT '{}',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS res_units (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        enterprise_id UUID REFERENCES enterprises(id),
        spbipk_id UUID REFERENCES spbipk(id),
        name VARCHAR(255) NOT NULL,
        code VARCHAR(50),
        extra JSONB DEFAULT '{}',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS departments (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        res_unit_id UUID REFERENCES res_units(id),
        name VARCHAR(255) NOT NULL,
        code VARCHAR(50),
        extra JSONB DEFAULT '{}',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        email VARCHAR(255),
        phone VARCHAR(50),
        role_id UUID REFERENCES roles(id),
        organization_id UUID REFERENCES organizations(id),
        enterprise_id UUID REFERENCES enterprises(id),
        res_unit_id UUID REFERENCES res_units(id),
        spbipk_id UUID REFERENCES spbipk(id),
        is_active BOOLEAN DEFAULT true,
        last_login TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS positions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        code VARCHAR(50),
        extra JSONB DEFAULT '{}',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS siz_categories (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        code VARCHAR(50),
        extra JSONB DEFAULT '{}',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS siz_items (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        category_id UUID REFERENCES siz_categories(id),
        name VARCHAR(255) NOT NULL,
        code VARCHAR(50),
        unit VARCHAR(50) DEFAULT 'шт',
        wear_period_months INTEGER DEFAULT 12,
        gender VARCHAR(10),
        season VARCHAR(20),
        exploitation_months INTEGER DEFAULT 12,
        exploitation_years NUMERIC,
        extra JSONB DEFAULT '{}',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS position_siz_norms (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        position_id UUID NOT NULL REFERENCES positions(id),
        siz_item_id UUID NOT NULL REFERENCES siz_items(id),
        quantity INTEGER DEFAULT 1,
        issue_period_months INTEGER DEFAULT 12,
        extra JSONB DEFAULT '{}',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(position_id, siz_item_id)
      );

      CREATE TABLE IF NOT EXISTS employees (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        employee_number VARCHAR(50),
        last_name VARCHAR(100),
        first_name VARCHAR(100),
        middle_name VARCHAR(100),
        position_id UUID REFERENCES positions(id),
        enterprise_id UUID REFERENCES enterprises(id),
        res_unit_id UUID REFERENCES res_units(id),
        department_id UUID REFERENCES departments(id),
        clothing_size VARCHAR(30),
        shoe_size VARCHAR(10),
        head_size VARCHAR(10),
        glove_size VARCHAR(10),
        extra JSONB DEFAULT '{}',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS siz_transactions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        employee_id UUID NOT NULL REFERENCES employees(id),
        siz_item_id UUID NOT NULL REFERENCES siz_items(id),
        transaction_type VARCHAR(20) NOT NULL,
        quantity INTEGER DEFAULT 1,
        transaction_date DATE DEFAULT CURRENT_DATE,
        valid_until DATE,
        issued_by UUID REFERENCES users(id),
        document_reference VARCHAR(255),
        notes TEXT,
        extra JSONB DEFAULT '{}',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS warehouses (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        warehouse_type VARCHAR(20) NOT NULL,
        spbipk_id UUID REFERENCES spbipk(id),
        res_unit_id UUID REFERENCES res_units(id),
        enterprise_id UUID REFERENCES enterprises(id),
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS warehouse_stock (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        warehouse_id UUID NOT NULL REFERENCES warehouses(id),
        siz_item_id UUID NOT NULL REFERENCES siz_items(id),
        size_value VARCHAR(30) DEFAULT '',
        quantity INTEGER NOT NULL DEFAULT 0,
        UNIQUE(warehouse_id, siz_item_id, size_value)
      );

      CREATE TABLE IF NOT EXISTS stock_movements (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        movement_type VARCHAR(20) NOT NULL,
        siz_item_id UUID NOT NULL REFERENCES siz_items(id),
        size_value VARCHAR(30) DEFAULT '',
        quantity INTEGER NOT NULL,
        from_warehouse_id UUID REFERENCES warehouses(id),
        to_warehouse_id UUID REFERENCES warehouses(id),
        employee_id UUID REFERENCES employees(id),
        document_reference VARCHAR(255),
        notes TEXT,
        moved_by UUID REFERENCES users(id),
        movement_date DATE NOT NULL DEFAULT CURRENT_DATE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS employee_siz (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        employee_id UUID NOT NULL REFERENCES employees(id),
        siz_item_id UUID NOT NULL REFERENCES siz_items(id),
        size_value VARCHAR(30) DEFAULT '',
        quantity INTEGER NOT NULL DEFAULT 1,
        issued_date DATE NOT NULL DEFAULT CURRENT_DATE,
        exploitation_start DATE,
        exploitation_paused_days INTEGER DEFAULT 0,
        status VARCHAR(20) DEFAULT 'active',
        returned_date DATE,
        from_warehouse_id UUID REFERENCES warehouses(id),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS siz_cards (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        card_number VARCHAR(50) UNIQUE NOT NULL,
        siz_item_id UUID NOT NULL REFERENCES siz_items(id),
        size_value VARCHAR(30) DEFAULT '',
        location_type VARCHAR(20) NOT NULL DEFAULT 'warehouse',
        warehouse_id UUID REFERENCES warehouses(id),
        employee_id UUID REFERENCES employees(id),
        enterprise_id UUID REFERENCES enterprises(id),
        res_unit_id UUID REFERENCES res_units(id),
        department_id UUID REFERENCES departments(id),
        manufacture_date DATE,
        receipt_date DATE DEFAULT CURRENT_DATE,
        issue_date DATE,
        exploitation_start DATE,
        exploitation_end DATE,
        status VARCHAR(20) DEFAULT 'in_stock',
        document_reference VARCHAR(255),
        notes TEXT,
        extra JSONB DEFAULT '{}',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS siz_card_movements (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        siz_card_id UUID NOT NULL REFERENCES siz_cards(id),
        movement_type VARCHAR(20) NOT NULL,
        from_warehouse_id UUID REFERENCES warehouses(id),
        to_warehouse_id UUID REFERENCES warehouses(id),
        from_employee_id UUID REFERENCES employees(id),
        to_employee_id UUID REFERENCES employees(id),
        document_reference VARCHAR(255),
        notes TEXT,
        moved_by UUID REFERENCES users(id),
        movement_date DATE NOT NULL DEFAULT CURRENT_DATE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS size_references (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        category_type VARCHAR(20) NOT NULL,
        size_value VARCHAR(30) NOT NULL,
        sort_order INTEGER DEFAULT 0,
        UNIQUE(category_type, size_value)
      );

      CREATE TABLE IF NOT EXISTS audit_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id),
        table_name VARCHAR(100),
        record_id UUID,
        action VARCHAR(20),
        changes JSONB DEFAULT '{}',
        ip_address VARCHAR(50),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS field_access_rules (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        role_id UUID REFERENCES roles(id),
        target_table VARCHAR(100),
        field_name VARCHAR(100) DEFAULT '*',
        access_level VARCHAR(20) DEFAULT 'read',
        conditions JSONB DEFAULT '{}',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(role_id, target_table, field_name)
      );
    `);
    console.log('Core tables created');

    // === Add spbipk_id to users if missing ===
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS spbipk_id UUID REFERENCES spbipk(id)");

    // === Add missing columns to employees ===
    await pool.query("ALTER TABLE employees ADD COLUMN IF NOT EXISTS clothing_size VARCHAR(30)");
    await pool.query("ALTER TABLE employees ADD COLUMN IF NOT EXISTS shoe_size VARCHAR(10)");
    await pool.query("ALTER TABLE employees ADD COLUMN IF NOT EXISTS head_size VARCHAR(10)");
    await pool.query("ALTER TABLE employees ADD COLUMN IF NOT EXISTS glove_size VARCHAR(10)");

    // === Add res_unit_id, department_id, enterprise_id to positions ===
    await pool.query("ALTER TABLE positions ADD COLUMN IF NOT EXISTS res_unit_id UUID REFERENCES res_units(id)");
    await pool.query("ALTER TABLE positions ADD COLUMN IF NOT EXISTS department_id UUID REFERENCES departments(id)");
    await pool.query("ALTER TABLE positions ADD COLUMN IF NOT EXISTS enterprise_id UUID REFERENCES enterprises(id)");

    // === Add exploitation_months to siz_items ===
    await pool.query("ALTER TABLE siz_items ADD COLUMN IF NOT EXISTS exploitation_months INTEGER DEFAULT 12");

    // === Seed default SIZ categories ===
    // One-time: rename old 'Одежда' and remove duplicates
    await pool.query("UPDATE siz_categories SET name='Спецодежда' WHERE name='Одежда' AND NOT EXISTS (SELECT 1 FROM siz_categories WHERE name='Спецодежда')");
    await pool.query(`DELETE FROM siz_categories WHERE id IN (
      SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY name ORDER BY created_at ASC) as rn FROM siz_categories) t WHERE rn > 1
    )`);
    const existingCats = (await pool.query("SELECT name FROM siz_categories")).rows.map(r => r.name);
    const defaultCats = [
      ['Спецодежда', 'clothes'], ['Обувь', 'shoes'], ['Каски', 'helmets'],
      ['СИЗ', 'ppe'], ['Перчатки', 'gloves'], ['Моющие средства', 'detergents']
    ];
    for (const [name, code] of defaultCats) {
      if (!existingCats.includes(name)) {
        await pool.query("INSERT INTO siz_categories (name, code) VALUES ($1, $2)", [name, code]);
      }
    }

    // === Fix level constraint to include spbipk ===
    await pool.query(`ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_level_check`);
    await pool.query(`ALTER TABLE roles ADD CONSTRAINT roles_level_check CHECK (level IN ('ia','enterprise','spbipk','res'))`);

    // === ROLES ===
    await pool.query(`
      INSERT INTO roles (name, display_name, level, description, general_permissions) VALUES
      ('admin_ia', 'Исполнительный аппарат', 'ia', 'Полный доступ ко всей системе',
       '{"can_create":true,"can_edit":true,"can_delete":true,"can_view_all":true,"can_manage_users":true}'::jsonb),
      ('admin_enterprise', 'Предприятие', 'enterprise', 'Просмотр данных предприятия (без редактирования)',
       '{"can_create":false,"can_edit":false,"can_delete":false,"can_view_all":false}'::jsonb),
      ('admin_spbipk', 'СПБиПК', 'spbipk', 'Управление персоналом, ТОН, перемещение СИЗ в пределах предприятия',
       '{"can_create":true,"can_edit":true,"can_delete":false,"can_view_all":false,"can_transfer":true}'::jsonb),
      ('admin_res', 'РЭС / Служба', 'res', 'Просмотр и управление СИЗ в пределах своего подразделения',
       '{"can_create":true,"can_edit":true,"can_delete":false,"can_view_all":false,"can_transfer":true}'::jsonb)
      ON CONFLICT (name) DO UPDATE SET
        display_name = EXCLUDED.display_name,
        general_permissions = EXCLUDED.general_permissions,
        description = EXCLUDED.description
    `);
    console.log('Roles seeded');

    // === ORGANIZATION ===
    await pool.query(`ALTER TABLE organizations ADD CONSTRAINT IF NOT EXISTS organizations_code_unique UNIQUE (code)`).catch(()=>{});
    await pool.query(`
      INSERT INTO organizations (name, code) VALUES ('Россети-Юг', 'Кубаньэнерго')
      ON CONFLICT (code) DO NOTHING
    `);
    console.log('Organization "Россети-Юг" ready');

    // === SIZE REFERENCES ===
    await pool.query(`
      INSERT INTO size_references (category_type, size_value, sort_order) VALUES
      ('shoes','35',1),('shoes','36',2),('shoes','37',3),('shoes','38',4),('shoes','39',5),
      ('shoes','40',6),('shoes','41',7),('shoes','42',8),('shoes','43',9),('shoes','44',10),
      ('shoes','45',11),('shoes','46',12),('shoes','47',13),('shoes','48',14),('shoes','49',15),
      ('clothing','40-42/158-164',1),('clothing','40-42/170-176',2),('clothing','40-42/182-188',3),('clothing','40-42/194-200',4),
      ('clothing','44-46/158-164',5),('clothing','44-46/170-176',6),('clothing','44-46/182-188',7),('clothing','44-46/194-200',8),
      ('clothing','48-50/158-164',9),('clothing','48-50/170-176',10),('clothing','48-50/182-188',11),('clothing','48-50/194-200',12),
      ('clothing','52-54/158-164',13),('clothing','52-54/170-176',14),('clothing','52-54/182-188',15),('clothing','52-54/194-200',16),
      ('clothing','56-58/158-164',17),('clothing','56-58/170-176',18),('clothing','56-58/182-188',19),('clothing','56-58/194-200',20),
      ('clothing','60-62/158-164',21),('clothing','60-62/170-176',22),('clothing','60-62/182-188',23),('clothing','60-62/194-200',24),
      ('clothing','64-66/158-164',25),('clothing','64-66/170-176',26),('clothing','64-66/182-188',27),('clothing','64-66/194-200',28),
      ('clothing','68-70/158-164',29),('clothing','68-70/170-176',30),('clothing','68-70/182-188',31),('clothing','68-70/194-200',32),
      ('clothing','72-74/158-164',33),('clothing','72-74/170-176',34),('clothing','72-74/182-188',35),('clothing','72-74/194-200',36),
      ('head','Универсальный',1),('gloves','Универсальный',1),('consumable','Ручной ввод',1)
      ON CONFLICT (category_type, size_value) DO NOTHING
    `);

    // === ADMIN USER ===
    const roleR = await db("SELECT id FROM roles WHERE name='admin_ia'");
    const orgR = await db("SELECT id FROM organizations LIMIT 1");
    if (roleR.rows.length && orgR.rows.length) {
      const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 12);
      await db(`INSERT INTO users (username, password_hash, full_name, email, role_id, organization_id)
        VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (username) DO NOTHING`,
        ['admin', hash, 'Администратор ИА', 'admin@rosseti-yug.local', roleR.rows[0].id, orgR.rows[0].id]);
      console.log('Admin user ready (login: admin / admin123)');
    }

    console.log('DB initialization complete');
  } catch (e) {
    console.error('DB init error:', e.message);
  }
}

initDB().then(() => {
  app.listen(PORT, () => console.log(`СИЗ Россети-Юг → http://localhost:${PORT}`));
});
