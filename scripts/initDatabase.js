const mysql = require('mysql2/promise');
require('dotenv').config();

const dbConfig = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
};

async function initDatabase() {
  let connection;
  
  try {
    connection = await mysql.createConnection(dbConfig);
    console.log('Connected to database');
    
    // Crear tablas
    const tables = [
      `CREATE TABLE IF NOT EXISTS perfil (
        id INT PRIMARY KEY AUTO_INCREMENT,
        nombre VARCHAR(50) NOT NULL UNIQUE,
        descripcion TEXT
      )`,
      
      `CREATE TABLE IF NOT EXISTS usuario (
        id INT PRIMARY KEY AUTO_INCREMENT,
        nombre VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        perfil_id INT NOT NULL,
        fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        activo BOOLEAN DEFAULT TRUE,
        FOREIGN KEY (perfil_id) REFERENCES perfil(id)
      )`,
      
      `CREATE TABLE IF NOT EXISTS marca (
        id INT PRIMARY KEY AUTO_INCREMENT,
        nombre VARCHAR(50) NOT NULL UNIQUE
      )`,
      
      `CREATE TABLE IF NOT EXISTS tipoEquipo (
        id INT PRIMARY KEY AUTO_INCREMENT,
        nombre VARCHAR(50) NOT NULL UNIQUE
      )`,
      
      `CREATE TABLE IF NOT EXISTS area (
        id INT PRIMARY KEY AUTO_INCREMENT,
        nombre VARCHAR(50) NOT NULL UNIQUE
      )`,
      
      `CREATE TABLE IF NOT EXISTS espacio (
        id INT PRIMARY KEY AUTO_INCREMENT,
        nombre VARCHAR(50) NOT NULL,
        area_id INT NOT NULL,
        capacidad INT DEFAULT 0,
        FOREIGN KEY (area_id) REFERENCES area(id)
      )`,
      
      `CREATE TABLE IF NOT EXISTS equipo (
        id INT PRIMARY KEY AUTO_INCREMENT,
        tipoEquipo_id INT NOT NULL,
        procesador VARCHAR(100),
        RAM VARCHAR(50),
        disco VARCHAR(50),
        marca_id INT NOT NULL,
        modelo VARCHAR(100),
        dimana VARCHAR(100),
        idarea VARCHAR(100),
        clasificacion VARCHAR(50),
        descripcion TEXT,
        fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        codigo_qr VARCHAR(255) UNIQUE,
        estado VARCHAR(50) DEFAULT 'Disponible',
        FOREIGN KEY (tipoEquipo_id) REFERENCES tipoEquipo(id),
        FOREIGN KEY (marca_id) REFERENCES marca(id)
      )`,
      
      `CREATE TABLE IF NOT EXISTS reporte (
        id INT PRIMARY KEY AUTO_INCREMENT,
        usuario_id INT NOT NULL,
        equipo_id INT NOT NULL,
        area_id INT NOT NULL,
        espacio_id INT NOT NULL,
        observacion TEXT,
        fechahora TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resuelto BOOLEAN DEFAULT FALSE,
        fecha_resolucion TIMESTAMP NULL,
        FOREIGN KEY (usuario_id) REFERENCES usuario(id),
        FOREIGN KEY (equipo_id) REFERENCES equipo(id),
        FOREIGN KEY (area_id) REFERENCES area(id),
        FOREIGN KEY (espacio_id) REFERENCES espacio(id)
      )`,
      
      `CREATE TABLE IF NOT EXISTS actividades (
        id INT PRIMARY KEY AUTO_INCREMENT,
        nombre VARCHAR(100) NOT NULL
      )`,
      
      `CREATE TABLE IF NOT EXISTS actividad (
        id INT PRIMARY KEY AUTO_INCREMENT,
        equipo_id INT NOT NULL,
        usuario_id INT NOT NULL,
        actividades_id INT NOT NULL,
        fechahora TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        observacion TEXT,
        fechafin TIMESTAMP NULL,
        FOREIGN KEY (equipo_id) REFERENCES equipo(id),
        FOREIGN KEY (usuario_id) REFERENCES usuario(id),
        FOREIGN KEY (actividades_id) REFERENCES actividades(id)
      )`
    ];
    
    // Crear cada tabla
    for (const table of tables) {
      await connection.execute(table);
      console.log('Tabla creada');
    }
    
    // Insertar datos básicos
    await connection.execute("INSERT IGNORE INTO perfil (nombre, descripcion) VALUES ('Administrador', 'Acceso completo al sistema')");
    await connection.execute("INSERT IGNORE INTO perfil (nombre, descripcion) VALUES ('Técnico', 'Gestión de mantenimientos y equipos')");
    await connection.execute("INSERT IGNORE INTO perfil (nombre, descripcion) VALUES ('Instructor', 'Reportes y monitoreo de aulas')");
    await connection.execute("INSERT IGNORE INTO perfil (nombre, descripcion) VALUES ('Aprendiz', 'Vinculación con equipos via QR')");
    
    await connection.execute("INSERT IGNORE INTO marca (nombre) VALUES ('HP'), ('Dell'), ('Lenovo'), ('ASUS'), ('Epson')");
    await connection.execute("INSERT IGNORE INTO tipoEquipo (nombre) VALUES ('Computador de escritorio'), ('Monitor'), ('Impresora'), ('Proyector')");
    await connection.execute("INSERT IGNORE INTO area (nombre) VALUES ('Bloque A'), ('Bloque B'), ('Laboratorio')");
    await connection.execute("INSERT IGNORE INTO espacio (nombre, area_id, capacidad) VALUES ('Aula 101', 1, 30), ('Aula 102', 1, 25), ('Lab Sistemas', 3, 20)");
    await connection.execute("INSERT IGNORE INTO actividades (nombre) VALUES ('Mantenimiento preventivo'), ('Mantenimiento correctivo'), ('Reparación')");
    
    // Usuarios de prueba
    await connection.execute("INSERT IGNORE INTO usuario (nombre, email, password, perfil_id) VALUES ('Administrador Sistema', 'admin@cba.sena.edu.co', 'password123', 1)");
    await connection.execute("INSERT IGNORE INTO usuario (nombre, email, password, perfil_id) VALUES ('Angel Carrillo', 'acarrillo@cba.sena.edu.co', 'password123', 2)");
    await connection.execute("INSERT IGNORE INTO usuario (nombre, email, password, perfil_id) VALUES ('Instructor Ejemplo', 'instructor@cba.sena.edu.co', 'password123', 3)");
    await connection.execute("INSERT IGNORE INTO usuario (nombre, email, password, perfil_id) VALUES ('Aprendiz Ejemplo', 'aprendiz@cba.sena.edu.co', 'password123', 4)");
    
    console.log('✅ Base de datos inicializada exitosamente');
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    if (connection) {
      await connection.end();
    }
  }
}

initDatabase();