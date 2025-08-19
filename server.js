require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./db');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

db.serialize(() => {
  const fs = require('fs');
  const schema = fs.readFileSync(__dirname + '/schema.sql', 'utf8');
  db.exec(schema);
});

function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({error: 'No token'});
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({error: 'Invalid token'});
  }
}

app.post('/api/register', (req, res) => {
  const { phone, password, consent } = req.body;
  if (!phone || !password) return res.status(400).json({error: 'phone & password required'});
  const hash = bcrypt.hashSync(password, 10);
  const c = consent ? 1 : 0;

  const stmt = db.prepare('INSERT INTO users (phone, password_hash, consent) VALUES (?, ?, ?)');
  stmt.run(phone, hash, c, function(err){
    if (err) {
      if (err.message.includes('UNIQUE')) return res.status(409).json({error: 'Phone already registered'});
      return res.status(500).json({error: 'DB error'});
    }
    const token = jwt.sign({ id: this.lastID, phone }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token });
  });
});

app.post('/api/login', (req, res) => {
  const { phone, password } = req.body;
  db.get('SELECT * FROM users WHERE phone = ?', [phone], (err, user) => {
    if (err || !user) return res.status(401).json({error: 'Invalid credentials'});
    if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({error: 'Invalid credentials'});
    const token = jwt.sign({ id: user.id, phone: user.phone }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token });
  });
});

app.get('/api/me', auth, (req, res) => {
  db.get('SELECT id, phone, consent, selling_status, balance FROM users WHERE id = ?', [req.user.id], (err, row) => {
    if (err || !row) return res.status(404).json({error: 'Not found'});
    res.json(row);
  });
});

app.post('/api/selling', auth, (req, res) => {
  const { action } = req.body;
  const nextStatus = action === 'start' ? 'started' : 'stopped';
  db.run('UPDATE users SET selling_status = ? WHERE id = ?', [nextStatus, req.user.id], function(err){
    if (err) return res.status(500).json({error: 'DB error'});
    res.json({ status: nextStatus });
  });
});

app.post('/api/withdraw', auth, (req, res) => {
  const { amount, method } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({error: 'Invalid amount'});
  db.get('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({error: 'User not found'});
    if (user.balance < amount) return res.status(400).json({error: 'Insufficient balance'});
    db.run('INSERT INTO withdrawals (user_id, amount, method) VALUES (?, ?, ?)', [req.user.id, amount, method], function(err){
      if (err) return res.status(500).json({error: 'DB error'});
      db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, req.user.id]);
      res.json({ message: 'Withdrawal request submitted', id: this.lastID });
    });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running on port ' + PORT));
