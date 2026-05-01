require('dotenv').config();
global.crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const bcrypt = require('bcrypt');
const cloudinary = require('cloudinary').v2;
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'productos.json');
const ADMIN_DATA_FILE = path.join(__dirname, 'admin_data.json');

// Conexión a MongoDB
mongoose.connect(process.env.MONGODB_URI, { dbName: 'gracopack' })
    .then(() => {
        console.log('✅ Conectado a MongoDB Atlas (DB: gracopack)');
        migrateData();
    })
    .catch(err => console.error('❌ Error de conexión a MongoDB:', err));

// Esquemas de Mongoose
const ProductSchema = new mongoose.Schema({
    codigo: String,
    nombre_es: String,
    nombre_en: String,
    descripcion_es: String,
    descripcion_en: String,
    dimension: String,
    unidad_empaque: String,
    categoria: String,
    imagen: String,
    isEco: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorSecret: String,
    imagen: String
});

// Transformar _id a id para compatibilidad con el frontend
const transformId = (doc, ret) => {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
};

ProductSchema.set('toJSON', { transform: transformId });
ProductSchema.set('toObject', { transform: transformId });
UserSchema.set('toJSON', { transform: transformId });
UserSchema.set('toObject', { transform: transformId });

const Product = mongoose.model('Product', ProductSchema);
const User = mongoose.model('User', UserSchema);

// Función de Migración (JSON -> MongoDB)
async function migrateData() {
    try {
        console.log('🔍 Verificando estado de la base de datos...');
        const productCount = await Product.countDocuments();
        if (productCount === 0 && fs.existsSync(DB_FILE)) {
            console.log('🚀 Migrando productos desde JSON a MongoDB...');
            const productsData = fs.readFileSync(DB_FILE, 'utf8');
            const products = JSON.parse(productsData);
            
            if (products.length > 0) {
                // Mongo asignará ObjectIds automáticamente si no hay _id
                const cleanProducts = products.map(({ id, ...rest }) => rest);
                await Product.insertMany(cleanProducts);
                console.log(`✅ ${products.length} productos migrados con éxito.`);
            }
        } else {
            console.log(`ℹ️ Hay ${productCount} productos en MongoDB.`);
        }

        const userCount = await User.countDocuments();
        if (userCount === 0 && fs.existsSync(ADMIN_DATA_FILE)) {
            console.log('🚀 Migrando usuarios desde JSON a MongoDB...');
            const users = JSON.parse(fs.readFileSync(ADMIN_DATA_FILE, 'utf8'));
            if (users.length > 0) {
                await User.insertMany(users);
                console.log(`✅ ${users.length} usuarios migrados.`);
            }
        }
    } catch (err) {
        console.error('❌ Error crítico en la migración:', err);
    }
}

// Configuración de secretos
const SESSION_SECRET = process.env.SESSION_SECRET || 'graco-secret-2026';
const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY || 'gracoDemo2026';
const ADMIN_SECURE_PATH = '/admin-portal-graco-secure';

// Configuración de Cloudinary
cloudinary.config({ 
    cloud_name: 'dgy2nqird', 
    api_key: '325593321465867', 
    api_secret: '2wrcJLB_GqfEnfWYz2kI7f9aI-I' 
});

// Eliminamos las constantes fijas y usamos las de arriba

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

// Eliminamos funciones de archivo JSON

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
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find().sort({ createdAt: -1 });
        console.log(`🔍 API: Enviando ${products.length} productos.`);
        res.json(products);
    } catch (err) {
        console.error('❌ Error API /api/products:', err);
        res.status(500).json({ error: 'Error al obtener productos' });
    }
});

app.get('/api/debug/db', async (req, res) => {
    try {
        const count = await Product.countDocuments();
        const usersCount = await User.countDocuments();
        const sample = await Product.findOne();
        res.json({
            status: 'connected',
            database: mongoose.connection.name,
            productsCount: count,
            usersCount: usersCount,
            sampleProduct: sample,
            envSet: !!process.env.MONGODB_URI
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Rutas API Protegidas (Dashboard)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (user && bcrypt.compareSync(password, user.password)) {
            if (user.twoFactorEnabled) {
                return res.json({ 
                    success: true, 
                    status: "2FA_REQUIRED",
                    message: "Se requiere segundo factor de autenticación"
                });
            }
            
            res.cookie('auth', SESSION_SECRET, { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 });
            res.json({ success: true });
        } else {
            res.status(401).json({ success: false, message: 'Credenciales inválidas' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// Rutas para 2FA y Usuarios
app.post('/admin/usuarios/crear', requireAuth, async (req, res) => {
    const { nombre, password, enable2FA, imageUrl } = req.body;
    try {
        const existingUser = await User.findOne({ username: nombre });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "El usuario ya existe" });
        }

        const newUser = new User({
            username: nombre,
            password: bcrypt.hashSync(password, 10),
            twoFactorEnabled: enable2FA === true || enable2FA === 'true',
            imagen: imageUrl || ''
        });

        let qrCodeUrl = null;
        if (newUser.twoFactorEnabled) {
            const secret = speakeasy.generateSecret({ name: `GracoPack: ${nombre}` });
            newUser.twoFactorSecret = secret.base32;
            qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
        }

        await newUser.save();
        res.json({ success: true, message: "Usuario creado correctamente", qrCodeUrl });
    } catch (err) {
        res.status(500).json({ error: 'Error al crear usuario' });
    }
});

app.get('/admin/2fa/setup', requireAuth, async (req, res) => {
    try {
        const admin = await User.findOne({ username: 'administracion' });
        if (!admin) return res.status(404).json({ error: "Admin no encontrado" });

        const secret = speakeasy.generateSecret({ name: "GracoPack Admin" });
        admin.twoFactorSecret = secret.base32; // Usamos esto como tempSecret temporalmente
        await admin.save();

        const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
        res.json({ qrCodeUrl });
    } catch (err) {
        res.status(500).json({ error: 'Error en setup 2FA' });
    }
});

app.post('/admin/2fa/verify-and-activate', requireAuth, async (req, res) => {
    const { token } = req.body;
    try {
        const admin = await User.findOne({ username: 'administracion' });
        const verified = speakeasy.totp.verify({
            secret: admin.twoFactorSecret,
            encoding: 'base32',
            token: token
        });

        if (verified) {
            admin.twoFactorEnabled = true;
            await admin.save();
            res.json({ success: true, message: "2FA activado correctamente" });
        } else {
            res.status(400).json({ success: false, message: "Código inválido" });
        }
    } catch (err) {
        res.status(500).json({ error: 'Error al verificar 2FA' });
    }
});

app.post('/admin/2fa/login-validate', async (req, res) => {
    const { username, token } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(401).json({ success: false, message: "Usuario inválido" });

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
    } catch (err) {
        res.status(500).json({ error: 'Error al validar 2FA' });
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

        if (req.file) {
            const result = await streamUpload(req.file.buffer, 'graco/productos');
            finalImageUrl = result.secure_url;
        }

        if (!finalImageUrl) return res.status(400).json({ error: 'La imagen es obligatoria' });

        const nuevoProducto = new Product({
            codigo, nombre_es, nombre_en, descripcion_es, descripcion_en,
            dimension, unidad_empaque, categoria,
            imagen: finalImageUrl,
            isEco: isEco === 'true' || isEco === true
        });

        await nuevoProducto.save();
        res.json({ success: true, message: "Producto guardado con éxito en la nube", producto: nuevoProducto });
    } catch (error) {
        res.status(500).json({ error: 'Error al guardar el producto', details: error.message });
    }
});

app.put('/api/products/:id', requireAuth, upload.single('imagen'), async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = { ...req.body };

        if (req.file) {
            const result = await streamUpload(req.file.buffer, 'graco/productos');
            updateData.imagen = result.secure_url;
        }

        if (updateData.isEco !== undefined) {
            updateData.isEco = updateData.isEco === 'true' || updateData.isEco === true;
        }

        const actualizado = await Product.findByIdAndUpdate(id, updateData, { new: true });
        if (!actualizado) return res.status(404).json({ error: 'Producto no encontrado' });

        res.json(actualizado);
    } catch (error) {
        res.status(500).json({ error: 'Error al editar producto', details: error.message });
    }
});

app.delete('/api/products/:id', requireAuth, async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Error al eliminar producto' });
    }
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
