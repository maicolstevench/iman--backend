const fs = require('fs');
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const bcrypt = require('bcryptjs');
const qrcode = require('qrcode');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Determinar si estamos en producción
const isProduction = process.env.NODE_ENV === 'production';

// Database connection pool
let dbConfig;

if (process.env.DATABASE_URL) {
  // Configuración para Railway
  const url = new URL(process.env.DATABASE_URL);
  dbConfig = {
    host: url.hostname,
    port: url.port || 3306,
    user: url.username,
    password: url.password,
    database: url.pathname.replace(/^\//, ''),
    ssl: {
      rejectUnauthorized: false
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    multipleStatements: true
  };
} else {
  // Configuración local
  dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'inman_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    multipleStatements: true
  };
}

const pool = mysql.createPool(dbConfig);

// Configuración del almacenamiento de sesiones
const sessionStore = new MySQLStore({
  clearExpired: true,
  checkExpirationInterval: 900000, // 15 minutos
  expiration: 86400000, // 24 horas
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

// Error handlers
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (err) => {
  console.error('❌ Unhandled Rejection:', err);
  process.exit(1);
});

// ✅ CONFIGURACIÓN CORS CORREGIDA
const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'https://frontend-inmanfinal.onrender.com'
];

app.use(cors({
  origin: function(origin, callback) {
    // Permitir peticiones sin origin (como Postman, apps móviles, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn('⚠️ Origen bloqueado por CORS:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ SESSION CONFIGURATION CORREGIDA
app.use(session({
  key: 'inman_session',
  secret: process.env.SESSION_SECRET || 'default-secret-key-change-in-production',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    secure: isProduction, // ✅ true en producción (HTTPS)
    httpOnly: true,
    sameSite: isProduction ? 'none' : 'lax' // ✅ 'none' necesario para CORS en producción
  }
}));

// Static files for QR codes
app.use('/uploads', express.static('uploads'));

// Create uploads directory
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}
if (!fs.existsSync('uploads/qr-codes')) {
  fs.mkdirSync('uploads/qr-codes', { recursive: true });
}

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

// Get user permissions based on profile - ACTUALIZADO PARA NUEVOS ROLES
const getUserPermissions = (rol) => {
  const key = (rol || '').toString().trim().toLowerCase();
  const permissionsMap = {
    'admin': {
      can_manage_users: true,
      can_manage_equipos: true,
      can_manage_reportes: true,
      can_manage_mantenimientos: true,
      can_view_dashboard: true,
      can_view_monitoreo: true,
      can_use_qr: true,
      modules: ['dashboard', 'equipos', 'reportes', 'monitoreo', 'mantenimientos', 'usuarios']
    },
    'tecnico': {
      can_manage_users: false,
      can_manage_equipos: true,
      can_manage_reportes: true,
      can_manage_mantenimientos: true,
      can_view_dashboard: true,
      can_view_monitoreo: true,
      can_use_qr: true,
      modules: ['dashboard', 'equipos', 'reportes', 'monitoreo', 'mantenimientos']
    },
    'usuario': {
      can_manage_users: false,
      can_manage_equipos: false,
      can_manage_reportes: false,
      can_manage_mantenimientos: false,
      can_view_dashboard: true,
      can_view_monitoreo: true,
      can_use_qr: false,
      can_create_reportes: true,
      modules: ['dashboard', 'equipos', 'reportes', 'monitoreo']
    },
    'instructor': {
      can_manage_users: false,
      can_manage_equipos: false,
      can_manage_reportes: false,
      can_manage_mantenimientos: false,
      can_view_dashboard: true,
      can_view_monitoreo: true,
      can_use_qr: false,
      can_create_reportes: true,
      can_send_to_maintenance: true,
      modules: ['dashboard', 'equipos', 'reportes', 'monitoreo']
    }
  };
  return permissionsMap[key] || {};
};

// ... [resto del código sin cambios]

// Start server
app.listen(PORT, () => {
  console.log(`✅ INMAN Backend running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔒 Secure cookies: ${isProduction}`);
  console.log(`🌐 Allowed origins:`, allowedOrigins);
}).on('error', (err) => {
  console.error('❌ Server startup error:', err);
});

module.exports = app;
