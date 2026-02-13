-- ============================================
-- СИЗ: Учет и движение
-- Инициализация базы данных
-- JSONB поля для гибкого расширения без миграций
-- ============================================

-- Расширения
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================
-- 1. ОРГАНИЗАЦИОННАЯ СТРУКТУРА
-- ============================================

-- Уровень 1: ИА (Исполнительный аппарат)
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50) UNIQUE,
    description TEXT,
    extra JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Уровень 2: Предприятия
CREATE TABLE IF NOT EXISTS enterprises (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50) UNIQUE,
    description TEXT,
    extra JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Уровень 3: РЭС
CREATE TABLE IF NOT EXISTS res_units (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    enterprise_id UUID REFERENCES enterprises(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50) UNIQUE,
    description TEXT,
    extra JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- 2. ПОЛЬЗОВАТЕЛИ И РОЛИ
-- ============================================

-- Роли в системе
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    level VARCHAR(20) NOT NULL CHECK (level IN ('ia', 'enterprise', 'res')),
    description TEXT,
    -- Гранулярные права на ячейки/поля: {"table_name": {"field_name": "read|write|none"}}
    field_permissions JSONB DEFAULT '{}',
    -- Общие права: {"can_create": true, "can_delete": false, ...}
    general_permissions JSONB DEFAULT '{"can_view": true, "can_create": false, "can_edit": false, "can_delete": false}',
    extra JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Пользователи
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    phone VARCHAR(50),
    role_id UUID REFERENCES roles(id),
    -- Привязка к уровню оргструктуры
    organization_id UUID REFERENCES organizations(id),
    enterprise_id UUID REFERENCES enterprises(id),
    res_unit_id UUID REFERENCES res_units(id),
    is_active BOOLEAN DEFAULT true,
    extra JSONB DEFAULT '{}',
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- 3. СПРАВОЧНИКИ СИЗ
-- ============================================

-- Категории СИЗ (КУВЭД, Моющие, Перчатки и т.д.)
CREATE TABLE IF NOT EXISTS siz_categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50) UNIQUE,
    description TEXT,
    -- Определяет структуру полей для этой категории
    -- {"fields": [{"key": "material", "label": "Материал", "type": "text"}, ...]}
    field_schema JSONB DEFAULT '{"fields": []}',
    extra JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Номенклатура СИЗ (конкретные наименования)
CREATE TABLE IF NOT EXISTS siz_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    category_id UUID REFERENCES siz_categories(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(100),
    unit VARCHAR(50) DEFAULT 'шт',
    description TEXT,
    -- Данные по полям категории: {"material": "latex", "size_range": "S-XL"}
    properties JSONB DEFAULT '{}',
    -- Сроки носки/годности (месяцев)
    wear_period_months INTEGER,
    extra JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- 4. РЕЕСТР ДОЛЖНОСТЕЙ
-- ============================================

CREATE TABLE IF NOT EXISTS positions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50),
    description TEXT,
    -- К какому уровню относится должность
    level VARCHAR(20) CHECK (level IN ('ia', 'enterprise', 'res')),
    extra JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Нормы выдачи СИЗ по должностям
CREATE TABLE IF NOT EXISTS position_siz_norms (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    position_id UUID REFERENCES positions(id) ON DELETE CASCADE,
    siz_item_id UUID REFERENCES siz_items(id) ON DELETE CASCADE,
    quantity INTEGER NOT NULL DEFAULT 1,
    -- Период выдачи (месяцев)
    issue_period_months INTEGER DEFAULT 12,
    -- Доп. условия и данные
    extra JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(position_id, siz_item_id)
);

-- ============================================
-- 5. РЕЕСТР СОТРУДНИКОВ (КАРТОЧКИ)
-- ============================================

CREATE TABLE IF NOT EXISTS employees (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- ФИО
    last_name VARCHAR(255) NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    middle_name VARCHAR(255),
    -- Табельный номер
    employee_number VARCHAR(50),
    position_id UUID REFERENCES positions(id),
    -- Привязка к оргструктуре
    organization_id UUID REFERENCES organizations(id),
    enterprise_id UUID REFERENCES enterprises(id),
    res_unit_id UUID REFERENCES res_units(id),
    -- Антропометрические данные и прочее
    -- {"height": 180, "clothing_size": "52", "shoe_size": "43", "head_size": "58"}
    personal_data JSONB DEFAULT '{}',
    extra JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    hire_date DATE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- 6. ДВИЖЕНИЕ СИЗ (ВЫДАЧА/ВОЗВРАТ)
-- ============================================

CREATE TABLE IF NOT EXISTS siz_transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    employee_id UUID REFERENCES employees(id) ON DELETE CASCADE,
    siz_item_id UUID REFERENCES siz_items(id),
    -- Тип операции
    transaction_type VARCHAR(20) NOT NULL CHECK (transaction_type IN ('issue', 'return', 'write_off', 'exchange')),
    quantity INTEGER NOT NULL DEFAULT 1,
    transaction_date DATE NOT NULL DEFAULT CURRENT_DATE,
    -- Срок годности/носки до
    valid_until DATE,
    -- Кто выдал/принял
    issued_by UUID REFERENCES users(id),
    -- Основание (номер приказа, акта и т.д.)
    document_reference VARCHAR(255),
    notes TEXT,
    -- Доп. информация: {"condition": "new", "certificate": "...", "batch": "..."}
    extra JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- 7. ЖУРНАЛ ИЗМЕНЕНИЙ (АУДИТ)
-- ============================================

CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    table_name VARCHAR(100) NOT NULL,
    record_id UUID NOT NULL,
    action VARCHAR(20) NOT NULL CHECK (action IN ('create', 'update', 'delete')),
    -- Что изменилось: {"field": "quantity", "old": 5, "new": 10}
    changes JSONB DEFAULT '{}',
    ip_address VARCHAR(45),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- 8. НАСТРОЙКИ ПРАВ ДОСТУПА К ПОЛЯМ
-- ============================================

-- Гранулярные права на уровне полей для ролей
CREATE TABLE IF NOT EXISTS field_access_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    target_table VARCHAR(100) NOT NULL,
    -- Конкретное поле или '*' для всех
    field_name VARCHAR(100) NOT NULL DEFAULT '*',
    -- Права: read, write, none
    access_level VARCHAR(10) NOT NULL DEFAULT 'read' CHECK (access_level IN ('read', 'write', 'none')),
    -- Дополнительные условия
    conditions JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(role_id, target_table, field_name)
);

-- ============================================
-- ИНДЕКСЫ
-- ============================================

CREATE INDEX IF NOT EXISTS idx_enterprises_org ON enterprises(organization_id);
CREATE INDEX IF NOT EXISTS idx_res_units_enterprise ON res_units(enterprise_id);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role_id);
CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_enterprise ON users(enterprise_id);
CREATE INDEX IF NOT EXISTS idx_users_res ON users(res_unit_id);
CREATE INDEX IF NOT EXISTS idx_siz_items_category ON siz_items(category_id);
CREATE INDEX IF NOT EXISTS idx_position_norms_position ON position_siz_norms(position_id);
CREATE INDEX IF NOT EXISTS idx_position_norms_item ON position_siz_norms(siz_item_id);
CREATE INDEX IF NOT EXISTS idx_employees_position ON employees(position_id);
CREATE INDEX IF NOT EXISTS idx_employees_res ON employees(res_unit_id);
CREATE INDEX IF NOT EXISTS idx_employees_enterprise ON employees(enterprise_id);
CREATE INDEX IF NOT EXISTS idx_transactions_employee ON siz_transactions(employee_id);
CREATE INDEX IF NOT EXISTS idx_transactions_item ON siz_transactions(siz_item_id);
CREATE INDEX IF NOT EXISTS idx_transactions_date ON siz_transactions(transaction_date);
CREATE INDEX IF NOT EXISTS idx_audit_table_record ON audit_log(table_name, record_id);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);

-- ============================================
-- НАЧАЛЬНЫЕ ДАННЫЕ
-- ============================================

-- Организация (ИА)
INSERT INTO organizations (name, code, description) VALUES
('Исполнительный аппарат', 'IA', 'Головная организация')
ON CONFLICT (code) DO NOTHING;

-- Предприятие
INSERT INTO enterprises (organization_id, name, code, description)
SELECT o.id, 'ЭС СПБиПК', 'ES-SPB', 'Предприятие электрических сетей СПБ и ПК'
FROM organizations o WHERE o.code = 'IA'
ON CONFLICT (code) DO NOTHING;

-- Роли
INSERT INTO roles (name, display_name, level, description, general_permissions) VALUES
('admin_ia', 'Администратор ИА', 'ia', 'Полный доступ ко всем предприятиям',
 '{"can_view": true, "can_create": true, "can_edit": true, "can_delete": true}'),
('dept_pbotipk', 'Департамент ПБОТиПК ИА', 'ia', 'Просмотр всех предприятий',
 '{"can_view": true, "can_create": false, "can_edit": false, "can_delete": false}'),
('enterprise_es', 'Предприятие ЭС СПБиПК', 'enterprise', 'Видит все РЭС предприятия',
 '{"can_view": true, "can_create": true, "can_edit": true, "can_delete": false}'),
('logist', 'Логист', 'enterprise', 'Логистика по всем РЭС',
 '{"can_view": true, "can_create": true, "can_edit": true, "can_delete": false}'),
('ot_specialist', 'Специалист по охране труда', 'res', 'Видит только свой РЭС',
 '{"can_view": true, "can_create": true, "can_edit": true, "can_delete": false}'),
('chief_engineer', 'Главный инженер РЭС', 'res', 'Видит только свой РЭС',
 '{"can_view": true, "can_create": false, "can_edit": false, "can_delete": false}'),
('head_urru', 'Начальник УРРУ', 'res', 'Видит только свой РЭС',
 '{"can_view": true, "can_create": false, "can_edit": true, "can_delete": false}')
ON CONFLICT (name) DO NOTHING;

-- Категории СИЗ
INSERT INTO siz_categories (name, code, description, field_schema) VALUES
('КУВЭД', 'KUVED', 'Комплекты для защиты от электродуги',
 '{"fields": [{"key": "protection_class", "label": "Класс защиты", "type": "select", "options": ["1", "2", "3"]}, {"key": "arc_rating", "label": "Рейтинг дуги (кал/см²)", "type": "number"}]}'),
('Моющие средства', 'WASH', 'Моющие и очищающие средства',
 '{"fields": [{"key": "volume_ml", "label": "Объем (мл)", "type": "number"}, {"key": "purpose", "label": "Назначение", "type": "text"}]}'),
('Перчатки', 'GLOVES', 'Перчатки различного назначения',
 '{"fields": [{"key": "material", "label": "Материал", "type": "select", "options": ["латекс", "нитрил", "кожа", "х/б", "диэлектрические"]}, {"key": "size_range", "label": "Размеры", "type": "text"}]}'),
('Каски', 'HELMETS', 'Защитные каски',
 '{"fields": [{"key": "color", "label": "Цвет", "type": "text"}, {"key": "has_visor", "label": "Наличие козырька", "type": "boolean"}]}'),
('Спецодежда', 'CLOTHING', 'Специальная одежда',
 '{"fields": [{"key": "season", "label": "Сезон", "type": "select", "options": ["летняя", "зимняя", "демисезонная"]}, {"key": "material", "label": "Материал", "type": "text"}]}'),
('Спецобувь', 'FOOTWEAR', 'Специальная обувь',
 '{"fields": [{"key": "season", "label": "Сезон", "type": "select", "options": ["летняя", "зимняя", "демисезонная"]}, {"key": "protection", "label": "Защита", "type": "text"}]}')
ON CONFLICT (code) DO NOTHING;

-- Триггер для автообновления updated_at
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['organizations','enterprises','res_units','roles','users',
        'siz_categories','siz_items','positions','position_siz_norms','employees',
        'siz_transactions','field_access_rules']
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS trigger_updated_at ON %I', t);
        EXECUTE format('CREATE TRIGGER trigger_updated_at BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION update_updated_at()', t);
    END LOOP;
END;
$$;
