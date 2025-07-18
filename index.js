const express = require('express');
const AWS = require('aws-sdk');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('./config/db');
require('dotenv').config();
const authenticateToken = require('./middleware/auth');

const app = express();
const upload = multer({ dest: 'uploads/' });

// Konfigurasi AWS S3
AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
});
const s3 = new AWS.S3();

// Middleware
app.use(express.json());
app.use(express.static('views'));

// Endpoint Registrasi
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
    res.status(201).send('Pengguna berhasil didaftarkan.');
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      res.status(400).send('Username sudah digunakan.');
    } else {
      res.status(500).send('Error saat registrasi.');
    }
  }
});

// Endpoint Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) return res.status(400).send('Pengguna tidak ditemukan.');

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send('Password salah.');

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).send('Error saat login.');
  }
});

// Endpoint Unggah File
app.post('/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    const fileContent = fs.readFileSync(req.file.path);
    const params = {
      Bucket: process.env.S3_BUCKET,
      Key: `${req.user.id}/${req.file.originalname}`,
      Body: fileContent,
    };

    const data = await s3.upload(params).promise();
    fs.unlinkSync(req.file.path); // Hapus file lokal

    await pool.query('INSERT INTO files (user_id, file_name, s3_url) VALUES (?, ?, ?)', [
      req.user.id,
      req.file.originalname,
      data.Location,
    ]);

    res.send(`File berhasil diunggah. Lokasi: ${data.Location}`);
  } catch (err) {
    res.status(500).send('Error saat mengunggah file.');
  }
});

// Endpoint Lihat File
app.get('/files', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT file_name, s3_url FROM files WHERE user_id = ?', [req.user.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).send('Error saat mengambil daftar file.');
  }
});

// Jalankan server
app.listen(3000, () => {
  console.log('Server berjalan di http://localhost:3000');
});