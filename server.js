require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const CLAVE_SECRETA = process.env.JWT_SECRET || "clave_por_defecto";

app.use(cors());
app.use(express.json());

// Conexión a MySQL con soporte para SSL (Aiven) y Local
const configDB = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'gestion_tareas',
    port: process.env.DB_PORT || 3306
};

// Aiven exige conexión SSL obligatoria
if (process.env.DB_HOST && process.env.DB_HOST.includes('aivencloud.com')) {
    configDB.ssl = { rejectUnauthorized: false };
}

const db = mysql.createConnection(configDB);

db.connect((err) => {
    if (err) {
        console.error("❌ Error al conectar a MySQL:", err.message);
        return;
    }
    console.log("✅ Conectado exitosamente a la base de datos MySQL.");
});

// Creación automática de tablas si no existen
const crearTablaUsuarios = `
    CREATE TABLE IF NOT EXISTS usuarios (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
    )
`;

const crearTablaTareas = `
    CREATE TABLE IF NOT EXISTS tareas (
        id INT AUTO_INCREMENT PRIMARY KEY,
        titulo VARCHAR(255) NOT NULL,
        prioridad VARCHAR(50) NOT NULL,
        usuario_id INT NOT NULL,
        FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    )
`;

db.query(crearTablaUsuarios, () => {
    db.query(crearTablaTareas, (err) => {
        if (!err) console.log("✅ Tablas verificadas/listas en la Base de Datos.");
    });
});

// Middleware JWT
function verificarToken(req, res, next) {
    const headerAuth = req.headers['authorization'];
    if (!headerAuth) return res.status(403).json({ error: "Acceso denegado. Se requiere token." });

    const token = headerAuth.split(' ')[1];
    jwt.verify(token, CLAVE_SECRETA, (err, usuarioDecodificado) => {
        if (err) return res.status(401).json({ error: "Token inválido o expirado." });
        req.usuario = usuarioDecodificado;
        next();
    });
}

// Rutas de Autenticación
app.post('/api/registro', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Datos incompletos" });

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const sql = "INSERT INTO usuarios (email, password) VALUES (?, ?)";
        db.query(sql, [email, passwordHash], (err) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: "El correo ya existe" });
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({ mensaje: "Usuario registrado con éxito" });
        });
    } catch (error) {
        res.status(500).json({ error: "Error interno" });
    }
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const sql = "SELECT * FROM usuarios WHERE email = ?";
    db.query(sql, [email], async (err, results) => {
        if (err || results.length === 0) return res.status(401).json({ error: "Credenciales inválidas" });

        const usuario = results[0];
        const esValida = await bcrypt.compare(password, usuario.password);
        if (!esValida) return res.status(401).json({ error: "Credenciales inválidas" });

        const token = jwt.sign({ id: usuario.id, email: usuario.email }, CLAVE_SECRETA, { expiresIn: '2h' });
        res.json({ mensaje: "Inicio de sesión exitoso", token, usuario: { id: usuario.id, email: usuario.email } });
    });
});

// Rutas protegidas de Tareas
app.get('/api/tareas', verificarToken, (req, res) => {
    const sql = "SELECT * FROM tareas WHERE usuario_id = ?";
    db.query(sql, [req.usuario.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/tareas', verificarToken, (req, res) => {
    const { titulo, prioridad } = req.body;
    if (!titulo) return res.status(400).json({ error: "El título es requerido" });

    const sql = "INSERT INTO tareas (titulo, prioridad, usuario_id) VALUES (?, ?, ?)";
    db.query(sql, [titulo, prioridad, req.usuario.id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: result.insertId, titulo, prioridad, usuario_id: req.usuario.id });
    });
});

app.delete('/api/tareas/:id', verificarToken, (req, res) => {
    const sql = "DELETE FROM tareas WHERE id = ? AND usuario_id = ?";
    db.query(sql, [req.params.id, req.usuario.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ mensaje: "Tarea eliminada correctamente" });
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor ejecutándose en el puerto ${PORT}`);
});