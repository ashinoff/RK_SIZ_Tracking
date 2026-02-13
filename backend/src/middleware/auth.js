const jwt = require('jsonwebtoken');
const { query } = require('../config/database');

const JWT_SECRET = process.env.JWT_SECRET || 'siz-secret-key-change-in-production';

// Аутентификация
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Требуется авторизация' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await query(
      `SELECT u.*, r.name as role_name, r.level as role_level, 
              r.general_permissions, r.field_permissions,
              r.display_name as role_display_name
       FROM users u 
       JOIN roles r ON u.role_id = r.id 
       WHERE u.id = $1 AND u.is_active = true`,
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Пользователь не найден' });
    }

    req.user = result.rows[0];
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Срок токена истек' });
    }
    return res.status(401).json({ error: 'Невалидный токен' });
  }
};

// Проверка уровня доступа по иерархии
const checkHierarchyAccess = (requiredLevels) => {
  return (req, res, next) => {
    const userLevel = req.user.role_level;
    if (!requiredLevels.includes(userLevel)) {
      // ia видит всё, enterprise видит свои РЭС, res видит только своё
      if (userLevel === 'ia') return next(); // ИА видит всё
      return res.status(403).json({ error: 'Недостаточно прав доступа' });
    }
    next();
  };
};

// Проверка общего права (can_view, can_create, can_edit, can_delete)
const checkPermission = (permission) => {
  return (req, res, next) => {
    const perms = req.user.general_permissions || {};
    if (!perms[permission]) {
      return res.status(403).json({ error: `Нет права: ${permission}` });
    }
    next();
  };
};

// Фильтр данных по иерархии видимости
const getVisibilityFilter = (user) => {
  const level = user.role_level;
  switch (level) {
    case 'ia':
      // Видит всё
      return { filter: '', params: [], startParam: 1 };
    case 'enterprise':
      // Видит только свое предприятие
      return {
        filter: 'enterprise_id = $',
        value: user.enterprise_id,
      };
    case 'res':
      // Видит только свой РЭС
      return {
        filter: 'res_unit_id = $',
        value: user.res_unit_id,
      };
    default:
      return { filter: '1=0', value: null }; // Ничего не видит
  }
};

// Проверка прав на конкретное поле
const checkFieldAccess = async (userId, tableName, fieldName, requiredAccess = 'read') => {
  const result = await query(
    `SELECT far.access_level 
     FROM field_access_rules far
     JOIN users u ON u.role_id = far.role_id
     WHERE u.id = $1 AND far.target_table = $2 
       AND (far.field_name = $3 OR far.field_name = '*')
     ORDER BY CASE WHEN far.field_name = '*' THEN 1 ELSE 0 END
     LIMIT 1`,
    [userId, tableName, fieldName]
  );

  if (result.rows.length === 0) {
    // Если нет специальных правил — используем общие права роли
    return true;
  }

  const level = result.rows[0].access_level;
  if (requiredAccess === 'read') return level !== 'none';
  if (requiredAccess === 'write') return level === 'write';
  return false;
};

// Middleware для проверки прав на поля при обновлении
const checkFieldPermissions = (tableName) => {
  return async (req, res, next) => {
    try {
      const updates = req.body;
      const deniedFields = [];

      for (const field of Object.keys(updates)) {
        const hasAccess = await checkFieldAccess(req.user.id, tableName, field, 'write');
        if (!hasAccess) {
          deniedFields.push(field);
        }
      }

      if (deniedFields.length > 0) {
        return res.status(403).json({
          error: 'Нет прав на изменение полей',
          denied_fields: deniedFields,
        });
      }

      next();
    } catch (err) {
      next(err);
    }
  };
};

const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '24h' });
};

module.exports = {
  authenticate,
  checkHierarchyAccess,
  checkPermission,
  getVisibilityFilter,
  checkFieldAccess,
  checkFieldPermissions,
  generateToken,
  JWT_SECRET,
};
