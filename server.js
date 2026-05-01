const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const bcrypt = require('bcrypt');
const cloudinary = require('cloudinary').v2;

const app = express();
const PORT = 3000;
const DB_FILE = path.join(__dirname, 'productos.json');
const ADMIN_DATA_FILE = path.join(__dirname, 'admin_data.json');

// Configuración de Cloudinary
cloudinary.config({ 
    cloud_name: 'dgy2nqird', 
    api_key: '325593321465867', 
    api_secret: '2wrcJLB_GqfEnfWYz2kI7f9aI-I' 
});

const ADMIN_SECRET_KEY = 'gracoDemo2026';
const ADMIN_SECURE_PATH = '/admin-portal-graco-secure';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Multer para manejar la subida de archivos (usamos memoria para Vercel)
const upload = multer({ storage: multer.memoryStorage() });

// Helper para subir a Cloudinary mediante Stream (más fiable que Data URI)
const streamUpload = (buffer, folder) => {
    return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
            { folder: folder },
            (error, result) => {
                if (error) {
                    console.error('CLOUDINARY ERROR:', error);
                    reject(error);
                } else {
                    resolve(result);
                }
            }
        );
        stream.end(buffer);
    });
};

// Credenciales (Ahora leídas de admin_data.json)
const SESSION_SECRET = 'graco-secret-2026';

function getAdminData() {
    return JSON.parse(fs.readFileSync(ADMIN_DATA_FILE, 'utf8'));
}

function saveAdminData(data) {
    fs.writeFileSync(ADMIN_DATA_FILE, JSON.stringify(data, null, 2));
}

// Middleware de Autenticación
const requireAuth = (req, res, next) => {
    if (req.cookies.auth === SESSION_SECRET) {
        next();
    } else {
        // En lugar de redirigir, devolvemos 401 para que el frontend maneje el login
        res.status(401).json({ error: 'No autorizado' });
    }
};

// Rutas API Públicas
app.get('/api/products', (req, res) => {
    fs.readFile(DB_FILE, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Error leyendo base de datos' });
        res.json(JSON.parse(data));
    });
});

// Rutas API Protegidas (Dashboard)
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const users = getAdminData();
    const user = users.find(u => u.username === username);

    if (user && bcrypt.compareSync(password, user.password)) {
        if (user.twoFactorEnabled) {
            return res.json({ 
                success: true, 
                status: "2FA_REQUIRED",
                message: "Se requiere segundo factor de autenticación"
            });
        }
        
        res.cookie('auth', SESSION_SECRET, { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 }); // 1 día
        res.json({ success: true });
    } else {
        res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }
});

// Rutas para 2FA y Usuarios
app.post('/admin/usuarios/crear', requireAuth, async (req, res) => {
    const { nombre, password, enable2FA, imageUrl } = req.body;
    const users = getAdminData();

    if (users.find(u => u.username === nombre)) {
        return res.status(400).json({ success: false, message: "El usuario ya existe" });
    }

    const newUser = {
        username: nombre,
        password: bcrypt.hashSync(password, 10),
        twoFactorEnabled: enable2FA === true || enable2FA === 'true',
        twoFactorSecret: null,
        imagen: imageUrl || ''
    };

    let qrCodeUrl = null;
    if (newUser.twoFactorEnabled) {
        const secret = speakeasy.generateSecret({ name: `GracoPack: ${nombre}` });
        newUser.twoFactorSecret = secret.base32;
        qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
    }

    users.push(newUser);
    saveAdminData(users);

    res.json({ 
        success: true, 
        message: "Usuario creado correctamente", 
        qrCodeUrl 
    });
});

app.get('/admin/2fa/setup', requireAuth, async (req, res) => {
    // Nota: Esto asume el usuario actual. En una app real usaríamos req.user.id
    // Para simplificar, usaremos el primer usuario que coincida con el admin base o el que tenga sesión activa
    // Pero como solo tenemos un SESSION_SECRET global, vamos a buscar por el username 'administracion'
    const admin = getAdminData().find(u => u.username === 'administracion');
    if (!admin) return res.status(404).json({ error: "Admin no encontrado" });

    const secret = speakeasy.generateSecret({ name: "GracoPack Admin" });
    admin.tempSecret = secret.base32;
    saveAdminData(getAdminData().map(u => u.username === 'administracion' ? admin : u));

    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
    res.json({ qrCodeUrl });
});

app.post('/admin/2fa/verify-and-activate', requireAuth, (req, res) => {
    const { token } = req.body;
    const users = getAdminData();
    const admin = users.find(u => u.username === 'administracion');

    const verified = speakeasy.totp.verify({
        secret: admin.tempSecret,
        encoding: 'base32',
        token: token
    });

    if (verified) {
        admin.twoFactorSecret = admin.tempSecret;
        admin.twoFactorEnabled = true;
        delete admin.tempSecret;
        saveAdminData(users.map(u => u.username === 'administracion' ? admin : u));
        res.json({ success: true, message: "2FA activado correctamente" });
    } else {
        res.status(400).json({ success: false, message: "Código inválido" });
    }
});

app.post('/admin/2fa/login-validate', (req, res) => {
    const { username, token } = req.body;
    const users = getAdminData();
    const user = users.find(u => u.username === username);

    if (!user) {
        return res.status(401).json({ success: false, message: "Usuario inválido" });
    }

    const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: token
    });

    if (verified) {
        res.cookie('auth', SESSION_SECRET, { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 });
        res.json({ success: true });
    } else {
        res.status(401).json({ success: false, message: "Código 2FA inválido" });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('auth');
    res.json({ success: true });
});

app.post('/api/products', requireAuth, upload.single('imagen'), async (req, res) => {
    try {
        const { codigo, nombre_es, nombre_en, descripcion_es, descripcion_en, dimension, unidad_empaque, categoria, isEco, imagen_url } = req.body;
        
        let finalImageUrl = imagen_url;

        // Si viene un archivo, lo subimos a Cloudinary usando Stream
        if (req.file) {
            try {
                const result = await streamUpload(req.file.buffer, 'graco/productos');
                finalImageUrl = result.secure_url;
            } catch (uploadError) {
                return res.status(500).json({ error: 'Error al subir imagen a Cloudinary', details: uploadError.message });
            }
        }

        if (!finalImageUrl) {
            return res.status(400).json({ error: 'La imagen es obligatoria (no se recibió archivo ni URL)' });
        }

        // Leer base de datos
        let productos = [];
        try {
            productos = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
        } catch (readError) {
            console.error('Error leyendo DB:', readError);
            return res.status(500).json({ error: 'Error al leer la base de datos', details: readError.message });
        }

        const nuevoProducto = {
            id: Date.now().toString(),
            codigo,
            nombre_es,
            nombre_en,
            descripcion_es,
            descripcion_en,
            dimension,
            unidad_empaque,
            categoria,
            imagen: finalImageUrl,
            isEco: isEco === 'true' || isEco === true
        };

        productos.push(nuevoProducto);
        
        try {
            fs.writeFileSync(DB_FILE, JSON.stringify(productos, null, 2));
        } catch (writeError) {
            console.error('Error escribiendo DB:', writeError);
            // Si falla aquí, es probable que estemos en Vercel (read-only)
            return res.status(500).json({ 
                error: 'Error al guardar en la base de datos', 
                details: writeError.message,
                hint: 'Si estás en Vercel, recuerda que el sistema de archivos es de solo lectura. Considera usar una base de datos real.'
            });
        }

        res.status(201).json(nuevoProducto);
    } catch (error) {
        console.error('ERROR CRÍTICO AL CREAR PRODUCTO:', error);
        res.status(500).json({ error: 'Error interno del servidor', details: error.message });
    }
});

app.put('/api/products/:id', requireAuth, upload.single('imagen'), async (req, res) => {
    try {
        const { id } = req.params;
        const { codigo, nombre_es, nombre_en, descripcion_es, descripcion_en, dimension, unidad_empaque, categoria, isEco, imagen_url } = req.body;
        
        let productos = [];
        try {
            productos = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
        } catch (readError) {
            return res.status(500).json({ error: 'Error al leer la base de datos' });
        }

        const idx = productos.findIndex(p => p.id === id);
        if (idx === -1) return res.status(404).json({ error: 'Producto no encontrado' });

        let finalImageUrl = imagen_url || productos[idx].imagen;

        if (req.file) {
            try {
                const result = await streamUpload(req.file.buffer, 'graco/productos');
                finalImageUrl = result.secure_url;
            } catch (uploadError) {
                return res.status(500).json({ error: 'Error al subir nueva imagen a Cloudinary' });
            }
        }

        productos[idx] = {
            ...productos[idx],
            codigo: codigo || productos[idx].codigo,
            nombre_es: nombre_es || productos[idx].nombre_es,
            nombre_en: nombre_en || productos[idx].nombre_en,
            descripcion_es: descripcion_es !== undefined ? descripcion_es : productos[idx].descripcion_es,
            descripcion_en: descripcion_en !== undefined ? descripcion_en : productos[idx].descripcion_en,
            dimension: dimension || productos[idx].dimension,
            unidad_empaque: unidad_empaque || productos[idx].unidad_empaque,
            categoria: categoria || productos[idx].categoria,
            imagen: finalImageUrl,
            isEco: isEco !== undefined ? (isEco === 'true' || isEco === true) : productos[idx].isEco
        };

        try {
            fs.writeFileSync(DB_FILE, JSON.stringify(productos, null, 2));
        } catch (writeError) {
            return res.status(500).json({ 
                error: 'Error al guardar cambios', 
                details: writeError.message,
                hint: 'En Vercel el sistema de archivos es de solo lectura.'
            });
        }
        
        res.json(productos[idx]);
    } catch (error) {
        console.error('ERROR AL ACTUALIZAR PRODUCTO:', error);
        res.status(500).json({ error: 'Error al editar producto', details: error.message });
    }
});

app.delete('/api/products/:id', requireAuth, (req, res) => {
    const { id } = req.params;
    
    fs.readFile(DB_FILE, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Error leyendo DB' });
        
        let productos = JSON.parse(data);
        productos = productos.filter(p => p.id !== id);

        fs.writeFile(DB_FILE, JSON.stringify(productos, null, 2), (err) => {
            if (err) return res.status(500).json({ error: 'Error guardando DB' });
            res.json({ success: true });
        });
    });
});

// Ruta especial oculta para el administrador
app.get(ADMIN_SECURE_PATH, (req, res) => {
    const key = req.query.key;
    
    // 1. Validar la clave secreta primero para mantener la ruta "oculta"
    if (key !== ADMIN_SECRET_KEY) {
        // Si la clave no coincide, simulamos un 404
        return res.status(404).send('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Error</title></head><body><pre>Cannot GET ' + ADMIN_SECURE_PATH + '</pre></body></html>');
    }

    // 2. Validar si el usuario tiene sesión iniciada
    if (req.cookies.auth !== SESSION_SECRET) {
        // Si no tiene sesión, redirigir al login guardando la URL actual (con la key)
        const currentUrl = req.originalUrl;
        return res.redirect(`/login?redirect=${encodeURIComponent(currentUrl)}`);
    }

    // 3. Si tiene la clave Y sesión iniciada, servimos el archivo
    res.sendFile(path.join(__dirname, 'private', 'admin.html'));
});

// Ruta para el login (ahora fuera de public)
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'login.html'));
});

// Alias para evitar romper redirecciones existentes si las hubiera
app.get('/login.html', (req, res) => res.redirect('/login'));

if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`Servidor de Graco Pack corriendo en http://localhost:${PORT}`);
    });
}

module.exports = app;
