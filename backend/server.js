const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// Khởi tạo kết nối tới Supabase qua DATABASE_URL trong file .env
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Bắt buộc khi kết nối lên Cloud Supabase
});

const JWT_SECRET = process.env.JWT_SECRET || 'secret_key';

// Tự động tạo bảng users và todos nếu chưa tồn tại trên Supabase
const initDatabase = async () => {
    try {
        // 1. Tạo bảng users
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
        `);
        // 2. Tạo bảng todos
        await pool.query(`
            CREATE TABLE IF NOT EXISTS todos (
                id SERIAL PRIMARY KEY,
                user_id INT REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                is_completed BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);
        console.log('🚀 Khởi tạo cấu trúc bảng Supabase thành công!');
    } catch (err) {
        console.error('❌ Lỗi khởi tạo cơ sở dữ liệu:', err.message);
    }
};
initDatabase();

// Middleware xác thực Token JWT để bảo vệ các tuyến đường CRUD
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- ROUTES AUTH (ĐĂNG KÝ / ĐĂNG NHẬP) ---
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Thiếu thông tin đăng ký!' });
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (username, password) VALUES ($1, $2)',
            [username, hashedPassword]
        );
        res.status(201).json({ message: 'Đăng ký thành công' });
    } catch (error) {
        res.status(400).json({ error: 'Tài khoản đã tồn tại hoặc lỗi dữ liệu' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: 'Sai tài khoản hoặc mật khẩu' });
        }

        // Tạo mã Token JWT hợp lệ trong 12 giờ
        const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token, username });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --- ROUTES TODOS (ĐỌC - THÊM - SỬA - XÓA) ---
app.get('/api/todos', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM todos WHERE user_id = $1 ORDER BY id ASC', [req.user.userId]);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/todos', authenticateToken, async (req, res) => {
    const { title } = req.body;
    if (!title) return res.status(400).json({ error: 'Nội dung công việc không được để trống' });
    
    try {
        const result = await pool.query(
            'INSERT INTO todos (title, user_id) VALUES ($1, $2) RETURNING *',
            [title, req.user.userId]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/api/todos/:id', authenticateToken, async (req, res) => {
    const { title, is_completed } = req.body;
    try {
        const result = await pool.query(
            'UPDATE todos SET title = $1, is_completed = $2 WHERE id = $3 AND user_id = $4 RETURNING *',
            [title, is_completed, req.params.id, req.user.userId]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Không tìm thấy việc cần sửa' });
        res.json(result.rows[0]);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/todos/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('DELETE FROM todos WHERE id = $1 AND user_id = $2', [req.params.id, req.user.userId]);
        res.json({ message: 'Xóa việc cần làm thành công' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🌍 Backend đang chạy ổn định tại port ${PORT}`));