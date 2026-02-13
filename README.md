# Учёт и движение СИЗ

Система учёта средств индивидуальной защиты (СИЗ) в РЭС электросетевых предприятий.

## Возможности

- **Справочники СИЗ** — категории (КУВЭД, Моющие, Перчатки и др.) и номенклатура
- **Реестр должностей** — с привязкой норм выдачи СИЗ (что положено и в каком количестве)
- **Реестр сотрудников** — индивидуальные карточки с полной историей движения СИЗ
- **Движение СИЗ** — выдача, возврат, списание, обмен
- **Отчёты** — просроченные СИЗ, сводка по РЭС
- **Оргструктура** — ИА → Предприятие → РЭС (трёхуровневая иерархия)
- **Права доступа** — ролевые + поуровневые (field-level) права
- **Журнал аудита** — все изменения фиксируются
- **Гибкая схема** — JSONB-поля позволяют добавлять данные без миграций

## Иерархия доступа

| Уровень | Роли | Видимость |
|---------|------|-----------|
| **ИА** | Админ ИА, Департамент ПБОТиПК | Все предприятия и РЭС |
| **Предприятие** | ЭС СПБиПК, Логист | Все РЭС своего предприятия |
| **РЭС** | Специалист ОТ, Главный инженер, Начальник УРРУ | Только свой РЭС |

## Технологии

- **Backend:** Node.js + Express + PostgreSQL (JSONB)
- **Frontend:** React + React Router
- **Auth:** JWT + role-based + field-level access
- **Deploy:** Render (PostgreSQL + Web Service)

## Быстрый старт

### 1. Клонировать и установить

```bash
git clone <repo-url>
cd siz-tracking
npm run install:all
```

### 2. Настроить .env

```bash
cp backend/.env.example backend/.env
# Отредактировать DATABASE_URL, JWT_SECRET
```

### 3. Инициализировать БД

```bash
npm run db:init
```

### 4. Запустить

```bash
# Два терминала:
npm run dev:backend   # Бэкенд на :5000
npm run dev:frontend  # Фронтенд на :3000
```

**Вход:** `admin` / `admin123`

## Деплой на Render

1. Создать PostgreSQL на Render (Free plan)
2. Создать Web Service, указать репозиторий GitHub
3. **Build Command:** `cd frontend && npm install && npm run build && cd ../backend && npm install`
4. **Start Command:** `cd backend && npm run db:init && node src/index.js`
5. Добавить Environment Variables:
   - `DATABASE_URL` — строка подключения к PostgreSQL
   - `JWT_SECRET` — случайная строка
   - `NODE_ENV` — `production`
   - `ADMIN_PASSWORD` — пароль администратора

Или использовать `render.yaml` (Blueprint) — всё настроится автоматически.

## Структура проекта

```
siz-tracking/
├── backend/
│   ├── sql/init.sql          # Схема БД
│   ├── src/
│   │   ├── config/database.js
│   │   ├── middleware/auth.js  # JWT + роли + поуровневые права
│   │   ├── utils/
│   │   │   ├── flex-crud.js    # Гибкий CRUD с JSONB
│   │   │   └── audit.js        # Аудит-лог
│   │   ├── routes/
│   │   │   ├── auth.js
│   │   │   ├── org-structure.js
│   │   │   ├── siz.js
│   │   │   ├── positions.js
│   │   │   ├── employees.js
│   │   │   ├── transactions.js
│   │   │   └── admin.js
│   │   ├── index.js
│   │   └── db-init.js
│   └── package.json
├── frontend/
│   ├── public/index.html
│   ├── src/
│   │   ├── components/
│   │   │   ├── auth/Login.js
│   │   │   ├── common/{Layout,Modal}.js
│   │   │   ├── dashboard/Dashboard.js
│   │   │   ├── employees/{Employees,EmployeeCard}.js
│   │   │   ├── transactions/Transactions.js
│   │   │   ├── directories/Directories.js
│   │   │   ├── positions/Positions.js
│   │   │   ├── org/OrgStructure.js
│   │   │   └── admin/{AdminUsers,AdminPermissions,AdminAudit}.js
│   │   ├── contexts/AuthContext.js
│   │   ├── utils/api.js
│   │   ├── styles/index.css
│   │   ├── App.js
│   │   └── index.js
│   └── package.json
├── render.yaml
└── package.json
```

## API Endpoints

| Метод | Путь | Описание |
|-------|------|----------|
| POST | /api/auth/login | Авторизация |
| POST | /api/auth/register | Регистрация (админ) |
| GET | /api/org/tree | Дерево оргструктуры |
| GET/POST | /api/siz/categories | Категории СИЗ |
| GET/POST | /api/siz/items | Номенклатура СИЗ |
| GET/POST | /api/positions | Должности |
| POST | /api/positions/:id/norms | Нормы выдачи |
| GET/POST | /api/employees | Сотрудники |
| GET | /api/employees/:id | Карточка (баланс + история) |
| GET/POST | /api/transactions | Движение СИЗ |
| GET | /api/transactions/reports/expired | Просроченные |
| GET | /api/transactions/reports/summary | Сводка по РЭС |
| GET/POST | /api/admin/field-rules | Правила доступа к полям |
| GET | /api/admin/audit | Журнал аудита |
