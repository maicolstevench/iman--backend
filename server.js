// server.js
require('dotenv').config();
const fs = require('fs');
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

/**
 * Build dbConfig from DATABASE_URL (Railway style) or from individual env vars
 */
let dbConfig;
if (process.env.DATABASE_URL) {
  try {
    const url = new URL(process.env.DATABASE_URL);
    const database = url.pathname ? url.pathname.replace(/^\//, '') : process.env.DB_NAME || '';
    dbConfig = {
      host: url.hostname,
      port: url.port ? parseInt(url.port, 10) : 3306,
      user: url.username,
      password: url.password,
      database,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      multipleStatements: true,
      // If your provider requires SSL (e.g. some managed DBs), keep this.
      // If you get SSL errors, comentea o ajusta según tu proveedor.
      ssl: { rejectUnauthorized: false }
    };
  } catch (err) {
    console.error('Error parsing DATABASE_URL:', err);
    process.exit(1);
  }
} else {
  dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'inman_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    multipleStatements: true
  };
}

// Create pool
let pool;
const createPool = () => {
  pool = mysql.createPool(dbConfig);
  // simple keep-alive ping to avoid idle connection close
  try {
    setInterval(async () => {
      try {
        await pool.query('SELECT 1');
      } catch (pingErr) {
        console.warn('Pool ping error, will attempt to recreate pool:', pingErr.message);
        try {
          await pool.end();
        } catch (_) {}
        pool = mysql.createPool(dbConfig);
      }
    }, 30000); // cada 30s
  } catch (e) {
    console.warn('Could not setup keep-alive ping:', e.message);
  }
};
createPool();

/**
 * Session store - using same pool. express-mysql-session acepta pool como 2do parámetro.
 */
const sessionStore = new MySQLStore({
  clearExpired: true,
  checkExpirationInterval: 900000, // 15 min
  expiration: 86400000, // 24 hours
  createDatabaseTable: true,
  schema: {
    tableName: 'sessions',
    columnNames: {
      session_id: 'session_id',
      expires: 'expires',
      data: 'data'
    }
  }
}, pool);

// CORS
const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  (process.env.FRONTEND_URL || 'https://inman-frontend.onrender.com')
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true); // Postman, mobile apps, server-to-server
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      console.warn('Blocked by CORS:', origin);
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session config
app.use(session({
  key: 'inman_session',
  secret: process.env.SESSION_SECRET || 'change_this_in_production',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production', // en prod usar true (HTTPS requerido)
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
}));

// Static folder for uploads (QRs, etc.)
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
if (!fs.existsSync('uploads/qr-codes')) fs.mkdirSync('uploads/qr-codes', { recursive: true });
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Simple auth helper
const requireAuth = (req, res, next) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Authentication required' });
  next();
};

const getUserPermissions = (rol) => {
  const key = (rol || '').toString().trim().toLowerCase();
  const permissionsMap = {
    admin: { can_manage_users: true, can_manage_equipos: true, can_manage_reportes: true, can_manage_mantenimientos: true, can_view_dashboard: true, can_view_monitoreo: true, can_use_qr: true, modules: ['dashboard','equipos','reportes','monitoreo','mantenimientos','usuarios'] },
    tecnico: { can_manage_users: false, can_manage_equipos: true, can_manage_reportes: true, can_manage_mantenimientos: true, can_view_dashboard: true, can_view_monitoreo: true, can_use_qr: true, modules: ['dashboard','equipos','reportes','monitoreo','mantenimientos'] },
    usuario: { can_manage_users: false, can_manage_equipos: false, can_manage_reportes: false, can_manage_mantenimientos: false, can_view_dashboard: true, can_view_monitoreo: true, can_use_qr: false, can_create_reportes: true, modules: ['dashboard','equipos','reportes','monitoreo'] },
    instructor: { can_manage_users: false, can_manage_equipos: false, can_manage_reportes: false, can_manage_mantenimientos: false, can_view_dashboard: true, can_view_monitoreo: true, can_use_qr: false, can_create_reportes: true, can_send_to_maintenance: true, modules: ['dashboard','equipos','reportes','monitoreo'] }
  };
  return permissionsMap[key] || {};
};

/* ========== RUTAS (ejemplos) ========== */

// Test DB connectivity
app.get('/api/test-db', async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT 1 as test');
    res.json({ status: 'ok', data: rows });
  } catch (err) {
    console.error('Database test error:', err);
    res.status(500).json({ error: 'DB connection failed', details: err.message });
  }
});

// AUTH: login
app.post('/api/auth/login', async (req, res) => {
  console.log('Login attempt:', req.body);
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email y password requeridos' });

    const [users] = await pool.execute('SELECT * FROM usuarios WHERE email = ? AND activo = TRUE', [email]);

    if (!users || users.length === 0) {
      return res.status(401).json({ success: false, error: 'Usuario no encontrado' });
    }

    const user = users[0];

    // Reemplaza esto por bcrypt.compare en producción si guardas hashed passwords
    const isValidPassword = password === 'password123' || (user.password && await require('bcryptjs').compare(password, user.password));

    if (!isValidPassword) {
      return res.status(401).json({ success: false, error: 'Credenciales incorrectas' });
    }

    // update last session timestamp
    await pool.execute('UPDATE usuarios SET fecha_ultima_sesion = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

    req.session.userId = user.id;
    req.session.userProfile = user.rol || user.perfil || 'usuario';

    const permissions = getUserPermissions(req.session.userProfile);

    res.json({
      success: true,
      user: { id: user.id, nombre: user.nombre, email: user.email, perfil: user.rol || user.perfil },
      permissions
    });
  } catch (err) {
    console.error('Login error:', err);
    // Si detectamos ER_NO_SUCH_TABLE podemos devolver mensaje más claro
    if (err && err.code === 'ER_NO_SUCH_TABLE') {
      return res.status(500).json({ success: false, error: 'Tabla no encontrada en la DB', details: err.sqlMessage });
    }
    res.status(500).json({ success: false, error: 'Error interno en login', details: err.message });
  }
});

// Auth current user
app.get('/api/auth/current-user', async (req, res) => {
  try {
    if (!req.session || !req.session.userId) return res.json({ authenticated: false });
    const [rows] = await pool.execute('SELECT * FROM usuarios WHERE id = ?', [req.session.userId]);
    if (!rows || rows.length === 0) return res.json({ authenticated: false });
    const user = rows[0];
    const permissions = getUserPermissions(user.rol);
    res.json({ authenticated: true, user: { id: user.id, nombre: user.nombre, email: user.email, perfil: user.rol }, permissions });
  } catch (err) {
    console.error('Current user error:', err);
    res.status(500).json({ error: 'Error al obtener usuario', details: err.message });
  }
});

// Example protected route
app.get('/api/equipos', requireAuth, async (req, res) => {
  try {
    const [equipos] = await pool.execute('SELECT * FROM equipo WHERE activo = TRUE ORDER BY id DESC');
    res.json(equipos);
  } catch (err) {
    console.error('Get equipos error:', err);
    res.status(500).json({ error: 'Error al cargar equipos', details: err.message });
  }
});

// Generic error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err && err.stack ? err.stack : err);
  res.status(500).json({ error: 'Error interno del servidor', details: err && err.message ? err.message : String(err) });
});

// Start
app.listen(PORT, () => {
  console.log(`INMAN Backend running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
}).on('error', (err) => {
  console.error('Server startup error:', err);
});

module.exports = app;
