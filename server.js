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

// Crear el pool de conexiones
const pool = mysql.createPool(dbConfig);

// Middleware para manejar errores de base de datos
app.use((err, req, res, next) => {
  console.error('Error en la base de datos:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Configuración de CORS
const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'https://frontend-inmanfinal.onrender.com',
  'https://inman-frontend.onrender.com'
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

// Importar e inicializar la base de datos
const { initDatabase } = require('./scripts/initDatabase');

// Inicializar la base de datos al iniciar
async function startServer() {
  try {
    console.log('Inicializando base de datos...');
    await initDatabase();
    console.log('✅ Base de datos inicializada correctamente');
    
    // Iniciar el servidor después de inicializar la base de datos
    app.listen(PORT, () => {
      console.log(`\n🚀 Servidor corriendo en puerto ${PORT}`);
      console.log(`📊 Dashboard: http://localhost:${PORT}/api/test-db`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}\n`);
    });
  } catch (error) {
    console.error('❌ Error al inicializar la base de datos:', error);
  }
}

// Iniciar todo
startServer();

// Configuración del almacenamiento de sesiones
const sessionStore = new MySQLStore({
  clearExpired: true,
  checkExpirationInterval: 900000, // 15 minutos
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

// Session configuration
app.use(session({
  key: 'inman_session',
  secret: process.env.SESSION_SECRET || 'default-secret-key-change-in-production',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    secure: false, // Set to true in production with HTTPS
    httpOnly: true
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

// CREAR EQUIPO - CORREGIDO PARA NUEVA ESTRUCTURA
app.post('/api/equipos', requireAuth, async (req, res) => {
  try {
    console.log('Datos recibidos:', req.body); // Para debugging
    
    const permissions = getUserPermissions(req.session.userProfile);
    if (!permissions.can_manage_equipos) {
      return res.status(403).json({ error: 'Sin permisos para crear equipos' });
    }
    
    const { 
      tipoEquipo_id, 
      marca_id, 
      modelo, 
      procesador, 
      RAM, 
      disco, 
      descripcion, 
      estado_id = 1,
      dimana,
      idarea,
      clasificacion
    } = req.body;
    
    // Convertir undefined a null para evitar el error
    const cleanValues = [
      tipoEquipo_id || null,
      marca_id || null, 
      modelo || null,
      procesador || null,
      RAM || null,
      disco || null,
      descripcion || null,
      estado_id || 1,
      dimana || null,
      idarea || null,
      clasificacion || null
    ];
    
    console.log('Valores limpiados:', cleanValues); // Para debugging
    
    const [result] = await pool.execute(
      'INSERT INTO equipo (tipoEquipo_id, marca_id, modelo, procesador, RAM, disco, descripcion, estado_id, dimana, idarea, clasificacion, fecha_registro) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())',
      cleanValues
    );
    
    const equipoId = result.insertId;
    
    // Generate QR code
    const codigoQR = `QR${equipoId.toString().padStart(3, '0')}${modelo ? modelo.substring(0, 3).toUpperCase() : 'EQP'}${equipoId.toString().padStart(3, '0')}`;
    
    await pool.execute(
      'UPDATE equipo SET codigo_qr = ? WHERE id = ?',
      [codigoQR, equipoId]
    );
    
    // Registrar actividad (solo si la tabla existe)
    try {
      await pool.execute(
        'INSERT INTO actividad (equipo_id, usuario_id, tipo_actividad, descripcion, estado_nuevo_id) VALUES (?, ?, ?, ?, ?)',
        [equipoId, req.session.userId, 'creacion', 'Registro inicial del equipo', estado_id || 1]
      );
    } catch (activityError) {
      console.warn('No se pudo registrar actividad:', activityError.message);
      // Continuar sin error si la tabla actividad no existe
    }
    
    res.status(201).json({ 
      id: equipoId, 
      codigo_qr: codigoQR, 
      message: 'Equipo creado exitosamente' 
    });
  } catch (error) {
    console.error('Create equipo error:', error);
    res.status(500).json({ error: 'Error al crear equipo', details: error.message });
  }
});

// ELIMINAR EQUIPO - CORREGIDO
app.delete('/api/equipos/:id', requireAuth, async (req, res) => {
  try {
    const permissions = getUserPermissions(req.session.userProfile);
    if (!permissions.can_manage_equipos) {
      return res.status(403).json({ error: 'Sin permisos para eliminar equipos' });
    }
    
    const { id } = req.params;
    
    // Cambiar estado a inactivo en lugar de eliminar
    const [result] = await pool.execute('UPDATE equipo SET activo = FALSE WHERE id = ?', [id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Equipo no encontrado' });
    }
    
    // Registrar actividad
    await pool.execute(
      'INSERT INTO actividad (equipo_id, usuario_id, tipo_actividad, descripcion) VALUES (?, ?, ?, ?)',
      [id, req.session.userId, 'baja', 'Equipo dado de baja']
    );
    
    res.json({ message: 'Equipo eliminado exitosamente' });
  } catch (error) {
    console.error('Delete equipo error:', error);
    res.status(500).json({ error: 'Error al eliminar equipo' });
  }
});

// AUTH ROUTES - CORREGIDOS PARA NUEVA ESTRUCTURA
app.post('/api/auth/login', async (req, res) => {
  console.log('Login attempt:', req.body);
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      console.log('Faltan credenciales');
      return res.status(400).json({ success: false, error: 'Email y contraseña son requeridos' });
    }
    
    console.log('Buscando usuario con email:', email);
    
    // Asegurarnos de seleccionar la columna de contraseña correcta
    const [users] = await pool.execute(
      'SELECT id, nombre, email, password as contrasena, perfil_id as rol, activo FROM usuario WHERE email = ? AND activo = TRUE',
      [email]
    );
    
    console.log('Usuarios encontrados:', users.length);
    
    if (users.length === 0) {
      console.log('Usuario no encontrado o inactivo');
      return res.status(401).json({ success: false, error: 'Usuario no encontrado o inactivo' });
    }
    
    const user = users[0];
    console.log('Usuario encontrado:', { id: user.id, email: user.email, rol: user.rol });
    
    // Comparación de contraseña (compatible con texto plano y bcrypt)
    let isValidPassword = false;
    
    // Si la contraseña en la base de datos es 'password123' (sin hashear)
    if (user.contrasena === 'password123' && password === 'password123') {
      isValidPassword = true;
    } 
    // Si la contraseña está hasheada con bcrypt
    else if (user.contrasena && user.contrasena.startsWith('$2a$')) {
      isValidPassword = await bcrypt.compare(password, user.contrasena);
    }
    
    console.log('Contraseña válida:', isValidPassword);
    
    if (!isValidPassword) {
      return res.status(401).json({ success: false, error: 'Credenciales incorrectas' });
    }
    
    // Actualizar última sesión
    await pool.execute(
      'UPDATE usuarios SET fecha_ultima_sesion = CURRENT_TIMESTAMP WHERE id = ?',
      [user.id]
    );
    
    req.session.userId = user.id;
    req.session.userProfile = user.rol; // CORREGIDO: usar 'rol' en lugar de 'perfil_nombre'
    
    const permissions = getUserPermissions(user.rol);
    
    res.json({
      success: true,
      user: {
        id: user.id,
        nombre: user.nombre,
        email: user.email,
        perfil: user.rol // CORREGIDO: usar 'rol'
      },
      permissions
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: 'Error en el login' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Error al cerrar sesión' });
    }
    res.json({ success: true });
  });
});

// CORREGIDO: current-user endpoint
app.get('/api/auth/current-user', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.json({ authenticated: false });
    }
    
    // CORREGIDO: Usar tabla 'usuarios' sin JOIN
    const [users] = await pool.execute(
      'SELECT * FROM usuarios WHERE id = ?',
      [req.session.userId]
    );
    
    if (users.length === 0) {
      return res.json({ authenticated: false });
    }
    
    const user = users[0];
    const permissions = getUserPermissions(user.rol); // CORREGIDO: usar 'rol'
    
    res.json({
      authenticated: true,
      user: {
        id: user.id,
        nombre: user.nombre,
        email: user.email,
        perfil: user.rol // CORREGIDO: usar 'rol'
      },
      permissions
    });
  } catch (error) {
    console.error('Current user error:', error);
    res.status(500).json({ error: 'Error al obtener usuario actual' });
  }
});

// DASHBOARD ROUTES - CORREGIDO PARA NUEVA ESTRUCTURA
app.get('/api/dashboard/stats', requireAuth, async (req, res) => {
  try {
    const permissions = getUserPermissions(req.session.userProfile);
    if (!permissions.can_view_dashboard) {
      return res.status(403).json({ error: 'Sin permisos para ver dashboard' });
    }
    
    // Equipment stats - CORREGIDO: usar estado_id con JOIN
    const [equiposStats] = await pool.execute(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN est.nombre = 'Disponible' THEN 1 ELSE 0 END) as disponibles,
        SUM(CASE WHEN est.nombre = 'Mantenimiento' THEN 1 ELSE 0 END) as mantenimiento,
        SUM(CASE WHEN est.nombre = 'Dañado' THEN 1 ELSE 0 END) as danados
      FROM equipo e
      JOIN estado est ON e.estado_id = est.id
      WHERE e.activo = TRUE
    `);
    
    // Recent activities (reemplazar reportes por actividades)
    const [recentActivities] = await pool.execute(`
      SELECT a.id, a.descripcion, a.fecha_actividad, u.nombre as usuario,
             CONCAT(te.nombre, ' - ', m.nombre, ' ', e.modelo) as equipo
      FROM actividad a
      JOIN usuarios u ON a.usuario_id = u.id
      JOIN equipo e ON a.equipo_id = e.id
      JOIN tipoEquipo te ON e.tipoEquipo_id = te.id
      JOIN marca m ON e.marca_id = m.id
      ORDER BY a.fecha_actividad DESC LIMIT 5
    `);
    
    const actividadesRecientes = recentActivities.map(activity => ({
      id: activity.id,
      usuario: activity.usuario,
      equipo: activity.equipo,
      descripcion: activity.descripcion && activity.descripcion.length > 100 ? 
        activity.descripcion.substring(0, 100) + '...' : activity.descripcion,
      fecha: new Date(activity.fecha_actividad).toLocaleDateString('es-ES', {
        day: '2-digit', month: '2-digit', year: 'numeric',
        hour: '2-digit', minute: '2-digit'
      })
    }));
    
    res.json({
      equipos_stats: equiposStats[0],
      actividades_recientes: actividadesRecientes
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Error al cargar estadísticas' });
  }
});

// EQUIPOS ROUTES - CORREGIDO
app.get('/api/equipos', requireAuth, async (req, res) => {
  try {
    const [equipos] = await pool.execute(`
      SELECT e.*, te.nombre as tipo_equipo, m.nombre as marca_nombre, est.nombre as estado_nombre, est.color as estado_color
      FROM equipo e
      JOIN tipoEquipo te ON e.tipoEquipo_id = te.id
      JOIN marca m ON e.marca_id = m.id
      JOIN estado est ON e.estado_id = est.id
      WHERE e.activo = TRUE
      ORDER BY e.id DESC
    `);
    
    res.json(equipos);
  } catch (error) {
    console.error('Get equipos error:', error);
    res.status(500).json({ error: 'Error al cargar equipos' });
  }
});

// BASIC DATA ROUTES - MANTENER LOS EXISTENTES PERO AGREGAR ESTADOS
app.get('/api/estados', requireAuth, async (req, res) => {
  try {
    const [estados] = await pool.execute('SELECT * FROM estado ORDER BY nombre');
    res.json(estados);
  } catch (error) {
    console.error('Get estados error:', error);
    res.status(500).json({ error: 'Error al cargar estados' });
  }
});

app.get('/api/marcas', requireAuth, async (req, res) => {
  try {
    const [marcas] = await pool.execute('SELECT * FROM marca ORDER BY nombre');
    res.json(marcas);
  } catch (error) {
    console.error('Get marcas error:', error);
    res.status(500).json({ error: 'Error al cargar marcas' });
  }
});

app.get('/api/tipos-equipo', requireAuth, async (req, res) => {
  try {
    const [tipos] = await pool.execute('SELECT * FROM tipoEquipo ORDER BY nombre');
    res.json(tipos);
  } catch (error) {
    console.error('Get tipos error:', error);
    res.status(500).json({ error: 'Error al cargar tipos de equipo' });
  }
});

// ACTIVIDADES ROUTES - NUEVO ENDPOINT
app.get('/api/actividades', requireAuth, async (req, res) => {
  try {
    const [actividades] = await pool.execute(`
      SELECT a.*, u.nombre as usuario_nombre, 
             te.nombre as equipo_tipo, m.nombre as equipo_marca, e.modelo as equipo_modelo,
             ea.nombre as estado_anterior, en.nombre as estado_nuevo
      FROM actividad a
      JOIN usuarios u ON a.usuario_id = u.id
      JOIN equipo e ON a.equipo_id = e.id
      JOIN tipoEquipo te ON e.tipoEquipo_id = te.id
      JOIN marca m ON e.marca_id = m.id
      LEFT JOIN estado ea ON a.estado_anterior_id = ea.id
      LEFT JOIN estado en ON a.estado_nuevo_id = en.id
      ORDER BY a.fecha_actividad DESC
    `);
    
    res.json(actividades);
  } catch (error) {
    console.error('Get actividades error:', error);
    res.status(500).json({ error: 'Error al cargar actividades' });
  }
});

// NUEVO: Crear actividad (soporte para crear reportes como actividad)
app.post('/api/actividades', requireAuth, async (req, res) => {
  try {
    const { equipo_id, tipo_actividad, descripcion, estado_anterior_id = null, estado_nuevo_id = null, observaciones = null } = req.body;

    if (!equipo_id || !tipo_actividad || !descripcion) {
      return res.status(400).json({ error: 'equipo_id, tipo_actividad y descripcion son requeridos' });
    }

    const [result] = await pool.execute(
      'INSERT INTO actividad (equipo_id, usuario_id, tipo_actividad, descripcion, estado_anterior_id, estado_nuevo_id, observaciones, fecha_actividad) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
      [equipo_id, req.session.userId, tipo_actividad, descripcion, estado_anterior_id, estado_nuevo_id, observaciones]
    );

    return res.status(201).json({ success: true, id: result.insertId });
  } catch (error) {
    console.error('Crear actividad error:', error);
    return res.status(500).json({ error: 'Error al crear actividad' });
  }
});

// NUEVOS ENDPOINTS DE REPORTES (usar tabla 'reporte' y vista 'v_reportes_list')
// Listar reportes
app.get('/api/reportes', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM v_reportes_list');
    res.json(rows);
  } catch (error) {
    console.error('Get reportes error:', error);
    res.status(500).json({ error: 'Error al cargar reportes' });
  }
});

// Crear reporte
app.post('/api/reportes', requireAuth, async (req, res) => {
  try {
    const permissions = getUserPermissions(req.session.userProfile);
    // Permitir crear reportes si el usuario tiene permiso explícito o si es admin/tecnico
    if (!permissions.can_create_reportes && !permissions.can_manage_reportes) {
      return res.status(403).json({ error: 'Sin permisos para crear reportes' });
    }

    const { equipo, observacion } = req.body;

    if (!equipo || !observacion || !String(observacion).trim()) {
      return res.status(400).json({ error: 'equipo y observacion son requeridos' });
    }

    const [result] = await pool.execute(
      'INSERT INTO reporte (equipo_id, usuario_id, observacion, resuelto, fechahora, created_at, updated_at) VALUES (?, ?, ?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)',
      [parseInt(equipo), req.session.userId, String(observacion).trim()]
    );

    res.status(201).json({ success: true, id: result.insertId });
  } catch (error) {
    console.error('Crear reporte error:', error);
    res.status(500).json({ error: 'Error al crear reporte' });
  }
});

// Resolver reporte
app.post('/api/reportes/:id/resolver', requireAuth, async (req, res) => {
  try {
    const permissions = getUserPermissions(req.session.userProfile);
    if (!permissions.can_manage_reportes) {
      return res.status(403).json({ error: 'Sin permisos para resolver reportes' });
    }

    const { id } = req.params;

    const [result] = await pool.execute(
      'UPDATE reporte SET resuelto = 1, fecha_resolucion = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Reporte no encontrado' });
    }

    res.json({ success: true, message: 'Reporte marcado como resuelto' });
  } catch (error) {
    console.error('Resolver reporte error:', error);
    res.status(500).json({ error: 'Error al resolver reporte' });
  }
});

// Enviar reporte a mantenimiento - NUEVO ENDPOINT
app.post('/api/reportes/:id/enviar-a-mantenimiento', requireAuth, async (req, res) => {
  try {
    const permissions = getUserPermissions(req.session.userProfile);
    console.log('Auth enviar-a-mantenimiento:', {
      userId: req.session.userId,
      role: req.session.userProfile,
      permissions
    });
    if (!permissions.can_manage_reportes && !permissions.can_manage_mantenimientos && !permissions.can_send_to_maintenance) {
      return res.status(403).json({ error: 'Sin permisos para enviar reportes a mantenimiento' });
    }

    const { id } = req.params;

    // Obtener el reporte y datos del equipo
    const [rows] = await pool.execute(
      `SELECT r.id as reporte_id, r.observacion, r.equipo_id, e.estado_id as equipo_estado_id
       FROM reporte r
       JOIN equipo e ON r.equipo_id = e.id
       WHERE r.id = ?`,
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Reporte no encontrado' });
    }

    const reporte = rows[0];

    // Obtener ID del estado 'Mantenimiento'
    const [estadoRows] = await pool.execute(
      "SELECT id, nombre FROM estado WHERE nombre IN ('Mantenimiento')"
    );

    const estadoMantenimiento = estadoRows.find(e => e.nombre === 'Mantenimiento');
    if (!estadoMantenimiento) {
      return res.status(500).json({ error: "Estado 'Mantenimiento' no configurado en la base de datos" });
    }

    // Actualizar estado del equipo a Mantenimiento
    await pool.execute(
      'UPDATE equipo SET estado_id = ?, fecha_actualizacion = CURRENT_TIMESTAMP WHERE id = ? ',
      [estadoMantenimiento.id, reporte.equipo_id]
    );

    // Crear actividad de mantenimiento
    const descripcion = `Mantenimiento generado desde reporte #${reporte.reporte_id}: ${reporte.observacion}`;
    const [activityResult] = await pool.execute(
      'INSERT INTO actividad (equipo_id, usuario_id, tipo_actividad, descripcion, estado_anterior_id, estado_nuevo_id, observaciones, fecha_actividad) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
      [reporte.equipo_id, req.session.userId, 'mantenimiento', descripcion, reporte.equipo_estado_id, estadoMantenimiento.id, null]
    );

    // Marcar reporte como resuelto/enviado
    await pool.execute(
      'UPDATE reporte SET resuelto = 1, fecha_resolucion = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [id]
    );

    res.status(201).json({ success: true, message: 'Reporte enviado a mantenimiento', actividad_id: activityResult.insertId });
  } catch (error) {
    console.error('Enviar a mantenimiento error:', error);
    res.status(500).json({ error: 'Error al enviar reporte a mantenimiento' });
  }
});

// Completar mantenimiento - NUEVO ENDPOINT
app.post('/api/actividades/:id/completar', requireAuth, async (req, res) => {
  try {
    // Solo el rol TECNICO puede completar mantenimientos
    if (req.session.userProfile !== 'tecnico') {
      return res.status(403).json({ error: 'Solo los técnicos pueden completar mantenimientos' });
    }

    const { id } = req.params;

    // Obtener la actividad
    const [rows] = await pool.execute('SELECT * FROM actividad WHERE id = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Actividad no encontrada' });
    }

    const actividad = rows[0];

    if (actividad.tipo_actividad !== 'mantenimiento') {
      return res.status(400).json({ error: 'La actividad no corresponde a un mantenimiento' });
    }

    // Obtener IDs de estado necesarios
    const [estadoRows] = await pool.execute(
      "SELECT id, nombre FROM estado WHERE nombre IN ('Mantenimiento', 'Disponible')"
    );

    const estadoMap = Object.fromEntries(estadoRows.map(e => [e.nombre, e.id]));
    const estadoMantenimientoId = estadoMap['Mantenimiento'];
    const estadoDisponibleId = estadoMap['Disponible'];

    if (!estadoMantenimientoId || !estadoDisponibleId) {
      return res.status(500).json({ error: 'Estados requeridos no configurados en la base de datos' });
    }

    // Actualizar el estado del equipo a Disponible
    await pool.execute(
      'UPDATE equipo SET estado_id = ?, fecha_actualizacion = CURRENT_TIMESTAMP WHERE id = ?',
      [estadoDisponibleId, actividad.equipo_id]
    );

    // Registrar nueva actividad de cierre de mantenimiento
    await pool.execute(
      'INSERT INTO actividad (equipo_id, usuario_id, tipo_actividad, descripcion, estado_anterior_id, estado_nuevo_id, observaciones) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [
        actividad.equipo_id,
        req.session.userId,
        'actualizacion',
        'Mantenimiento completado',
        estadoMantenimientoId,
        estadoDisponibleId,
        null
      ]
    );

    const completionTime = new Date().toISOString();
    res.json({ success: true, message: 'Mantenimiento completado', fechafin: completionTime });
  } catch (error) {
    console.error('Completar mantenimiento error:', error);
    res.status(500).json({ error: 'Error al completar mantenimiento' });
  }
});

// Test database connection
app.get('/api/test-db', async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT 1 as test');
    res.json({ status: 'Database connected successfully', data: rows });
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).json({ error: 'Database connection failed', details: error.message });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Start server
app.listen(PORT, () => {
  console.log(` INMAN Backend running on port ${PORT}`);
  console.log(` Dashboard: http://localhost:${PORT}/api/test-db`);
  console.log(` Environment: ${process.env.NODE_ENV}`);
}).on('error', (err) => {
  console.error(' Server startup error:', err);
});

module.exports = app;
