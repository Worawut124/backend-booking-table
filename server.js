/* eslint-disable no-unused-vars */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 5000;

// Rate Limiters
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 attempts per window
    message: { success: false, message: 'พยายามมากเกินไป กรุณารอ 15 นาที' },
    standardHeaders: true,
    legacyHeaders: false
});

const generalLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 100, // 100 requests per minute
    message: { success: false, message: 'คำขอมากเกินไป กรุณารอสักครู่' }
});

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const BCRYPT_SALT_ROUNDS = 12;

// Helper function to generate JWT token
const generateToken = (userId, email, role) => {
    return jwt.sign(
        { userId, email, role },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );
};

// Helper function to verify JWT token
const verifyToken = (token) => {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch {
        return null;
    }
};

// Middleware to authenticate requests
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access token required' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }

    req.user = decoded;
    next();
};

// Middleware to check admin role
const requireAdmin = (req, res, next) => {
    const adminRoles = ['admin', 'owner'];
    if (!adminRoles.includes(req.user.role)) {
        return res.status(403).json({ success: false, message: 'Admin access required' });
    }
    next();
};

// Multer configuration (memory storage)
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit
    },
    fileFilter: (req, file, cb) => {
        // Accept images only
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('Only image files are allowed!'), false);
        }
        cb(null, true);
    }
});

// Middleware
// Security headers with Helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: false, // Allow external resources
}));

app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(generalLimiter);
app.use(express.json({ limit: '50mb' })); // Increase limit for large payloads
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('❌ Missing Supabase Environment Variables!');
    console.error('SUPABASE_URL:', supabaseUrl ? 'Set' : 'MISSING');
    console.error('SUPABASE_ANON_KEY:', supabaseKey ? 'Set' : 'MISSING');
}

const supabase = createClient(
    supabaseUrl || '',
    supabaseKey || ''
);

// Nodemailer configuration for password reset emails
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: process.env.SMTP_PORT || 587,
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD
    },
    pool: {
        maxConnections: 5,
        maxMessages: 100,
        rateDelta: 4000,
        rateLimit: 14
    },
    logger: false,
    debug: false
});

// Verify transporter connection on startup
transporter.verify((error, success) => {
    if (error) {
        console.error('⚠️  Email transporter verification failed:', error.message);
        console.error('Please check your SMTP configuration in .env file');
    }
});

// Function to generate password reset token
const generateResetToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

// Function to send password reset email
const sendPasswordResetEmail = async (email, name, resetToken) => {
    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    
    const mailOptions = {
        from: process.env.EMAIL_FROM_ADDRESS || process.env.SMTP_USER,
        to: email,
        subject: 'รีเซ็ตรหัสผ่าน | Password Reset',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">รีเซ็ตรหัสผ่าน</h2>
                <p>สวัสดี ${name},</p>
                <p>เราได้รับคำขอให้รีเซ็ตรหัสผ่านของคุณ โปรดคลิกที่ลิงก์ด้านล่างเพื่อสร้างรหัสผ่านใหม่:</p>
                <a href="${resetLink}" style="display: inline-block; padding: 12px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0;">
                    รีเซ็ตรหัสผ่าน
                </a>
                <p>หรือคัดลอกลิงก์นี้ไปยังเบราว์เซอร์:</p>
                <p style="word-break: break-all; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">
                    ${resetLink}
                </p>
                <p style="color: #666; font-size: 12px;">ลิงก์นี้จะหมดอายุใน 1 ชั่วโมง</p>
                <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                <p style="color: #999; font-size: 12px;">ถ้าคุณไม่ได้ขอการรีเซ็ตรหัสผ่าน โปรดเพิกเฉยต่อข้อความนี้</p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('❌ Email sending error:', error.message);
        return false;
    }
};

// Helper function to convert snake_case to camelCase
const toCamelCase = (obj) => {
    if (Array.isArray(obj)) {
        return obj.map(v => toCamelCase(v));
    } else if (obj !== null && obj.constructor === Object) {
        return Object.keys(obj).reduce((result, key) => {
            const camelKey = key.replace(/_([a-z])/g, (g) => g[1].toUpperCase());
            result[camelKey] = toCamelCase(obj[key]);
            return result;
        }, {});
    }
    return obj;
};

// Helper function to convert camelCase to snake_case
const toSnakeCase = (obj) => {
    if (Array.isArray(obj)) {
        return obj.map(v => toSnakeCase(v));
    } else if (obj !== null && obj.constructor === Object) {
        return Object.keys(obj).reduce((result, key) => {
            const snakeKey = key.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
            result[snakeKey] = toSnakeCase(obj[key]);
            return result;
        }, {});
    }
    return obj;
};

// ==================== ROUTES ====================

// Health check
app.get('/', (req, res) => {
    res.json({ status: 'OK', message: 'Backend is running' });
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Backend is running' });
});

// ==================== AUTH ====================

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name, phone } = req.body;

        // Validate input
        if (!email || !password || !name) {
            return res.status(400).json({ error: 'Email, password, and name are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        // Check if user exists
        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('email', email.toLowerCase())
            .single();

        if (existingUser) {
            return res.status(400).json({ error: 'อีเมลนี้ถูกใช้งานแล้ว' });
        }

        // Hash password with bcrypt
        const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

        // Create user with hashed password
        const { data, error } = await supabase
            .from('users')
            .insert([{
                email: email.toLowerCase(),
                password: hashedPassword,
                name,
                phone,
                role: 'user',
                created_at: new Date().toISOString()
            }])
            .select()
            .single();

        if (error) throw error;

        const user = toCamelCase(data);
        delete user.password;

        // Generate JWT token
        const token = generateToken(user.id, user.email, user.role);

        res.json({ success: true, user, token });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'กรุณากรอกอีเมลและรหัสผ่าน'
            });
        }

        // Get user by email (need to fetch password for bcrypt comparison)
        const { data, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email.toLowerCase())
            .single();

        if (error || !data) {
            return res.status(401).json({
                success: false,
                message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง'
            });
        }

        // Verify password with bcrypt
        const isValidPassword = await bcrypt.compare(password, data.password);

        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง'
            });
        }

        const user = toCamelCase(data);
        delete user.password;

        // Generate JWT token
        const token = generateToken(user.id, user.email, user.role);

        res.json({ success: true, user, token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Verify session
app.post('/api/auth/verify', async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(401).json({ success: false, message: 'No token provided' });
        }

        // Verify JWT token
        const decoded = verifyToken(token);

        if (!decoded) {
            return res.status(401).json({ success: false, message: 'Invalid or expired token' });
        }

        const { data, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', decoded.userId)
            .single();

        if (error || !data) {
            return res.status(401).json({ success: false, message: 'User not found' });
        }

        const user = toCamelCase(data);
        delete user.password;

        res.json({ success: true, user });
    } catch (error) {
        console.error('Verify error:', error);
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
});

// Update profile
app.put('/api/auth/profile/:userId', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.params;
        const updates = req.body;

        // Remove sensitive fields
        delete updates.id;
        delete updates.password;
        delete updates.role;
        delete updates.createdAt;

        const { data, error } = await supabase
            .from('users')
            .update(toSnakeCase(updates))
            .eq('id', userId)
            .select()
            .single();

        if (error) throw error;

        const user = toCamelCase(data);
        delete user.password;

        res.json({ success: true, user });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Change password
app.put('/api/auth/change-password/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { currentPassword, newPassword } = req.body;

        // Validate input
        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'กรุณากรอกรหัสผ่านปัจจุบันและรหัสผ่านใหม่'
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'รหัสผ่านใหม่ต้องมีอย่างน้อย 6 ตัวอักษร'
            });
        }

        // Get current user
        const { data: userData, error: userError } = await supabase
            .from('users')
            .select('*')
            .eq('id', userId)
            .single();

        if (userError || !userData) {
            return res.status(404).json({
                success: false,
                message: 'ไม่พบผู้ใช้'
            });
        }

        // Verify current password
        const isValidPassword = await bcrypt.compare(currentPassword, userData.password);

        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'รหัสผ่านปัจจุบันไม่ถูกต้อง'
            });
        }

        // Hash new password
        const hashedNewPassword = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);

        // Update password
        const { error: updateError } = await supabase
            .from('users')
            .update({ password: hashedNewPassword })
            .eq('id', userId);

        if (updateError) throw updateError;

        res.json({ success: true, message: 'เปลี่ยนรหัสผ่านสำเร็จ' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Refresh token
app.post('/api/auth/refresh', async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(401).json({ success: false, message: 'No token provided' });
        }

        // Verify current token (even if expired, we can still decode it)
        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET, { ignoreExpiration: true });
        } catch {
            return res.status(401).json({ success: false, message: 'Invalid token' });
        }

        // Check if user still exists
        const { data, error } = await supabase
            .from('users')
            .select('id, email, role')
            .eq('id', decoded.userId)
            .single();

        if (error || !data) {
            return res.status(401).json({ success: false, message: 'User not found' });
        }

        // Generate new token
        const newToken = generateToken(data.id, data.email, data.role);

        res.json({ success: true, token: newToken });
    } catch (error) {
        console.error('Refresh token error:', error);
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
});

// Forgot password - Generate and send reset token
app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
    try {
        const { email } = req.body;

        // Validate input
        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'กรุณากรอกอีเมล'
            });
        }

        // Check if user exists
        const { data: userData, error: userError } = await supabase
            .from('users')
            .select('id, email, name')
            .eq('email', email.toLowerCase())
            .single();

        if (userError || !userData) {
            // Don't reveal if email exists for security
            return res.status(200).json({
                success: true,
                message: 'ถ้าบัญชีนี้มีอยู่ ลิงก์รีเซ็ตรหัสผ่านจะถูกส่งไปยังอีเมลของคุณ'
            });
        }

        // Generate reset token
        const resetToken = generateResetToken();
        const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
        const resetExpiry = new Date(Date.now() + 3600000); // 1 hour from now

        // Update user with reset token
        const { error: updateError } = await supabase
            .from('users')
            .update({
                password_reset_token: resetTokenHash,
                password_reset_expires_at: resetExpiry.toISOString()
            })
            .eq('id', userData.id);

        if (updateError) throw updateError;

        // Send email
        const emailSent = await sendPasswordResetEmail(userData.email, userData.name, resetToken);

        if (!emailSent) {
            console.error('⚠️  Email sending failed for:', userData.email);
            throw new Error('ไม่สามารถส่งอีเมลรีเซ็ตได้ โปรดลองใหม่ในภายหลัง');
        }

        res.json({
            success: true,
            message: 'ถ้าบัญชีนี้มีอยู่ ลิงก์รีเซ็ตรหัสผ่านจะถูกส่งไปยังอีเมลของคุณ'
        });
    } catch (error) {
        console.error('❌ Forgot password error:', error.message);
        res.status(500).json({
            success: false,
            message: error.message || 'เกิดข้อผิดพลาด กรุณาลองใหม่'
        });
    }
});

// Reset password - Verify token and reset password
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        // Validate input
        if (!token || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'โทเค็นและรหัสผ่านใหม่จำเป็น'
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร'
            });
        }

        // Hash the reset token for comparison
        const resetTokenHash = crypto.createHash('sha256').update(token).digest('hex');

        // Find user with matching reset token that hasn't expired
        const { data: userData, error: userError } = await supabase
            .from('users')
            .select('id, email')
            .eq('password_reset_token', resetTokenHash)
            .gt('password_reset_expires_at', new Date().toISOString())
            .single();

        if (userError || !userData) {
            return res.status(400).json({
                success: false,
                message: 'โทเค็นรีเซ็ตไม่ถูกต้องหรือหมดอายุ'
            });
        }

        // Hash new password
        const hashedNewPassword = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);

        // Update password and clear reset token
        const { error: updateError } = await supabase
            .from('users')
            .update({
                password: hashedNewPassword,
                password_reset_token: null,
                password_reset_expires_at: null
            })
            .eq('id', userData.id);

        if (updateError) throw updateError;

        res.json({
            success: true,
            message: 'รีเซ็ตรหัสผ่านสำเร็จ โปรดเข้าสู่ระบบด้วยรหัสผ่านใหม่'
        });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({
            success: false,
            message: 'เกิดข้อผิดพลาด กรุณาลองใหม่'
        });
    }
});

// Change password (for logged-in users)
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
    try {
        const { userId, currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'กรุณากรอกรหัสผ่านปัจจุบันและรหัสผ่านใหม่'
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'รหัสผ่านใหม่ต้องมีอย่างน้อย 6 ตัวอักษร'
            });
        }

        // Get user
        const { data: userData, error: userError } = await supabase
            .from('users')
            .select('id, password')
            .eq('id', userId)
            .single();

        if (userError || !userData) {
            return res.status(404).json({
                success: false,
                message: 'ไม่พบผู้ใช้'
            });
        }

        // Verify current password with bcrypt
        const isValidPassword = await bcrypt.compare(currentPassword, userData.password);
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'รหัสผ่านปัจจุบันไม่ถูกต้อง'
            });
        }

        // Hash new password
        const hashedNewPassword = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);

        // Update password
        const { error: updateError } = await supabase
            .from('users')
            .update({ password: hashedNewPassword })
            .eq('id', userId);

        if (updateError) throw updateError;

        res.json({
            success: true,
            message: 'เปลี่ยนรหัสผ่านสำเร็จ'
        });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({
            success: false,
            message: 'เกิดข้อผิดพลาดในการเปลี่ยนรหัสผ่าน'
        });
    }
});

// ==================== USERS (Admin) ====================

const ALLOWED_ROLES = ['user', 'admin', 'owner'];

// Get all users
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('id, email, name, phone, role, created_at, avatar_url')
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Create user
app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { email, password, name, phone, role } = req.body;

        if (!email || !password || !name) {
            return res.status(400).json({ error: 'กรุณากรอกอีเมล รหัสผ่าน และชื่อ' });
        }

        // Validate role
        const normalizedRole = (role || 'user').toLowerCase();
        if (!ALLOWED_ROLES.includes(normalizedRole)) {
            return res.status(400).json({ error: 'สิทธิ์ไม่ถูกต้อง (ต้องเป็น user, admin หรือ owner)' });
        }

        // Hash password with bcrypt
        const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

        // Check unique email
        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .maybeSingle();

        if (existingUser) {
            return res.status(400).json({ error: 'อีเมลนี้ถูกใช้งานแล้ว' });
        }

        const { data, error } = await supabase
            .from('users')
            .insert([{
                email,
                password: hashedPassword,
                name,
                phone,
                role: normalizedRole,
                created_at: new Date().toISOString(),
            }])
            .select('id, email, name, phone, role, created_at, avatar_url')
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update user
app.put('/api/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { email, password, name, phone, role } = req.body;

        const updates = { email, name, phone };
        if (role) {
            const normalizedRole = role.toLowerCase();
            if (!ALLOWED_ROLES.includes(normalizedRole)) {
                return res.status(400).json({ error: 'สิทธิ์ไม่ถูกต้อง (ต้องเป็น user, admin หรือ owner)' });
            }
            updates.role = normalizedRole;
        }
        if (password && password.trim()) {
            // Hash password if updating
            updates.password = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
        }

        // If email provided, ensure not duplicate
        if (email) {
            const { data: existingUser } = await supabase
                .from('users')
                .select('id')
                .eq('email', email)
                .neq('id', userId)
                .maybeSingle();

            if (existingUser) {
                return res.status(400).json({ error: 'อีเมลนี้ถูกใช้งานแล้ว' });
            }
        }

        const { data, error } = await supabase
            .from('users')
            .update(toSnakeCase(updates))
            .eq('id', userId)
            .select('id, email, name, phone, role, created_at, avatar_url')
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Delete user
app.delete('/api/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;

        const { error } = await supabase
            .from('users')
            .delete()
            .eq('id', userId);

        if (error) throw error;

        res.json({ success: true });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==================== CONCERTS ====================

// Get all concerts
app.get('/api/concerts', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('concerts')
            .select('*')
            .order('date', { ascending: false });

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Get concerts error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get concert by ID
app.get('/api/concerts/:id', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('concerts')
            .select('*')
            .eq('id', req.params.id)
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Get concert error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Create concert
app.post('/api/concerts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const concertData = toSnakeCase(req.body);

        const { data, error } = await supabase
            .from('concerts')
            .insert([concertData])
            .select()
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Create concert error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update concert
app.put('/api/concerts/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const concertData = toSnakeCase(req.body);

        const { data, error } = await supabase
            .from('concerts')
            .update(concertData)
            .eq('id', req.params.id)
            .select()
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Update concert error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Delete concert
app.delete('/api/concerts/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { error } = await supabase
            .from('concerts')
            .delete()
            .eq('id', req.params.id);

        if (error) throw error;

        res.json({ success: true });
    } catch (error) {
        console.error('Delete concert error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==================== BOOKINGS ====================

// Get bookings by concert
app.get('/api/bookings/concert/:concertId', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('bookings')
            .select('*')
            .eq('concert_id', req.params.concertId)
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Get bookings error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get bookings by phone
app.get('/api/bookings/phone/:phone', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('bookings')
            .select('*')
            .eq('customer_phone', req.params.phone)
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Get bookings error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Create booking
app.post('/api/bookings', async (req, res) => {
    try {
        const bookingData = toSnakeCase(req.body);

        const { data, error } = await supabase
            .from('bookings')
            .insert([bookingData])
            .select()
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Create booking error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update booking
app.put('/api/bookings/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const bookingData = toSnakeCase(req.body);

        const { data, error } = await supabase
            .from('bookings')
            .update(bookingData)
            .eq('id', req.params.id)
            .select()
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Update booking error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Delete booking
app.delete('/api/bookings/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { error } = await supabase
            .from('bookings')
            .delete()
            .eq('id', req.params.id);

        if (error) throw error;

        res.json({ success: true });
    } catch (error) {
        console.error('Delete booking error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==================== LAYOUTS ====================

// Get all layouts
app.get('/api/layouts', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('layouts')
            .select('*')
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Get layouts error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get layout by ID
app.get('/api/layouts/:id', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('layouts')
            .select('*')
            .eq('id', req.params.id)
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Get layout error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Create layout
app.post('/api/layouts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const layoutData = toSnakeCase(req.body);

        const { data, error } = await supabase
            .from('layouts')
            .insert([layoutData])
            .select()
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Create layout error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update layout
app.put('/api/layouts/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const layoutData = toSnakeCase(req.body);

        const { data, error } = await supabase
            .from('layouts')
            .update(layoutData)
            .eq('id', req.params.id)
            .select()
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Update layout error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Delete layout
app.delete('/api/layouts/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { error } = await supabase
            .from('layouts')
            .delete()
            .eq('id', req.params.id);

        if (error) throw error;

        res.json({ success: true });
    } catch (error) {
        console.error('Delete layout error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==================== SETTINGS ====================

// Get settings
app.get('/api/settings', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('settings')
            .select('*')
            .limit(1)
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Get settings error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update settings
app.put('/api/settings/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const settingsData = toSnakeCase(req.body);

        const { data, error } = await supabase
            .from('settings')
            .update(settingsData)
            .eq('id', req.params.id)
            .select()
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Update settings error:', error);
        res.status(500).json({ error: error.message });
    }
});


// ==================== FILE UPLOAD ====================

// Generic upload endpoint for all file types
app.post('/api/upload/:bucket', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const { bucket } = req.params;
        const validBuckets = ['carousel-images', 'avatars', 'concert-images', 'payment-slips', 'brand-logos'];

        if (!validBuckets.includes(bucket)) {
            return res.status(400).json({ error: 'Invalid bucket' });
        }

        const file = req.file;
        const fileExt = file.originalname.split('.').pop();
        const fileName = `${Date.now()}-${Math.random().toString(36).substring(7)}.${fileExt}`;

        // Organize files in folders based on bucket
        let folderName = '';
        switch (bucket) {
            case 'carousel-images':
                folderName = 'carousel';
                break;
            case 'avatars':
                folderName = 'users';
                break;
            case 'concert-images':
                folderName = 'concerts';
                break;
            case 'payment-slips':
                folderName = 'slips';
                break;
            case 'brand-logos':
                folderName = 'branding';
                break;
        }

        const filePath = `${folderName}/${fileName}`;

        // Upload to Supabase Storage
        const { error } = await supabase.storage
            .from(bucket)
            .upload(filePath, file.buffer, {
                contentType: file.mimetype,
                cacheControl: '3600',
                upsert: false
            });

        if (error) throw error;

        // Get public URL
        const { data: { publicUrl } } = supabase.storage
            .from(bucket)
            .getPublicUrl(filePath);

        res.json({
            success: true,
            url: publicUrl,
            path: filePath,
            bucket: bucket
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Legacy endpoint for backward compatibility
app.post('/api/upload', upload.single('file'), async (req, res) => {
    req.params = { bucket: 'carousel-images' };
    return app._router.handle(req, res);
});

// ==================== CAROUSEL SLIDES ====================

// Get all active carousel slides
app.get('/api/carousel', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('carousel_slides')
            .select('*')
            .eq('is_active', true)
            .order('display_order', { ascending: true });

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Get carousel slides error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get all carousel slides (for admin)
app.get('/api/carousel/all', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('carousel_slides')
            .select('*')
            .order('display_order', { ascending: true });

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Get all carousel slides error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get carousel slide by ID
app.get('/api/carousel/:id', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('carousel_slides')
            .select('*')
            .eq('id', req.params.id)
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Get carousel slide error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Create carousel slide
app.post('/api/carousel', async (req, res) => {
    try {
        const slideData = toSnakeCase(req.body);

        const { data, error } = await supabase
            .from('carousel_slides')
            .insert([slideData])
            .select()
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Create carousel slide error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update carousel slide
app.put('/api/carousel/:id', async (req, res) => {
    try {
        const slideData = toSnakeCase(req.body);
        slideData.updated_at = new Date().toISOString();

        const { data, error } = await supabase
            .from('carousel_slides')
            .update(slideData)
            .eq('id', req.params.id)
            .select()
            .single();

        if (error) throw error;

        res.json(toCamelCase(data));
    } catch (error) {
        console.error('Update carousel slide error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Delete carousel slide
app.delete('/api/carousel/:id', async (req, res) => {
    try {
        const { error } = await supabase
            .from('carousel_slides')
            .delete()
            .eq('id', req.params.id);

        if (error) throw error;

        res.json({ success: true });
    } catch (error) {
        console.error('Delete carousel slide error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
    console.log(`🚀 Backend server running on http://localhost:${PORT}`);
    console.log(`📊 API endpoints available at http://localhost:${PORT}/api`);
});
