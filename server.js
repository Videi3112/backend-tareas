const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const CLAVE_SECRETA = "mi_clave_secreta_super_segura_123"; // Clave privada para firmar tokens

app.use(cors());
app.use(express.json());

// Conexión a MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'gestion_tareas'
});

db.connect((err) => {
    if (err) {
        console.error("❌ Error al conectar a MySQL:", err.message);
        return;
    }
    console.log("✅ Conectado exitosamente a MySQL (XAMPP).");
});

// Creación de tablas
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
        if (!err) console.log("✅ Tablas listas en MySQL.");
    });
});

// ==========================================
// MIDDLEWARE DE AUTENTICACIÓN (JWT)
// ==========================================
function verificarToken(req, res, next) {
    const headerAuth = req.headers['authorization'];
    
    // El formato esperado en la cabecera es: "Bearer TOKEN"
    if (!headerAuth) {
        return res.status(403).json({ error: "Acceso denegado. Se requiere un token." });
    }

    const token = headerAuth.split(' ')[1];

    jwt.verify(token, CLAVE_SECRETA, (err, usuarioDecodificado) => {
        if (err) {
            return res.status(401).json({ error: "Token inválido o expirado." });
        }
        // Guardamos los datos decodificados en el objeto de la petición (req)
        req.usuario = usuarioDecodificado;
        next();
    });
}

// ==========================================
// RUTAS PÚBLICAS (AUTENTICACIÓN)
// ==========================================

app.post('/api/registro', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Datos incompletos" });

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const sql = "INSERT INTO usuarios (email, password) VALUES (?, ?)";
        db.query(sql, [email, passwordHash], (err, result) => {
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

        // Firma y emisión del Token JWT (expira en 2 horas)
        const token = jwt.sign(
            { id: usuario.id, email: usuario.email },
            CLAVE_SECRETA,
            { expiresIn: '2h' }
        );

        res.json({
            mensaje: "Inicio de sesión exitoso",
            token: token,
            usuario: { id: usuario.id, email: usuario.email }
        });
    });
});

// ==========================================
// RUTAS PROTEGIDAS CON JWT
// ==========================================

// Obtener tareas del usuario autenticado
app.get('/api/tareas', verificarToken, (req, res) => {
    const usuarioId = req.usuario.id;
    const sql = "SELECT * FROM tareas WHERE usuario_id = ?";
    db.query(sql, [usuarioId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Crear tarea para el usuario autenticado
app.post('/api/tareas', verificarToken, (req, res) => {
    const { titulo, prioridad } = req.body;
    const usuarioId = req.usuario.id;

    if (!titulo) return res.status(400).json({ error: "El título es requerido" });

    const sql = "INSERT INTO tareas (titulo, prioridad, usuario_id) VALUES (?, ?, ?)";
    db.query(sql, [titulo, prioridad, usuarioId], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: result.insertId, titulo, prioridad, usuario_id: usuarioId });
    });
});

// Eliminar tarea (solo si pertenece al usuario)
app.delete('/api/tareas/:id', verificarToken, (req, res) => {
    const tareaId = req.params.id;
    const usuarioId = req.usuario.id;

    const sql = "DELETE FROM tareas WHERE id = ? AND usuario_id = ?";
    db.query(sql, [tareaId, usuarioId], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ mensaje: "Tarea eliminada correctamente" });
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor protegido con JWT en http://localhost:${PORT}`);
});