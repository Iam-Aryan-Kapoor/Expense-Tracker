const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const db = new sqlite3.Database('./database.db');

app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'expense_secret_key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false
  }
}));

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`);

db.run(`CREATE TABLE IF NOT EXISTS expenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  amount REAL,
  category TEXT,
  date TEXT,
  note TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
)`);

app.post('/signup', (req, res) => {
  const { username, password } = req.body;
  bcrypt.hash(password, 10, (err, hash) => {
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function(err) {
      if (err) return res.status(400).send('Username already exists');
      req.session.userId = this.lastID;
      res.redirect('/tracker.html');
    });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (!user) return res.status(400).send('User not found');
    bcrypt.compare(password, user.password, (err, match) => {
      if (match) {
        req.session.userId = user.id;
        res.redirect('/tracker.html');
      } else {
        res.status(401).send('Invalid credentials');
      }
    });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/index.html'));
});

app.get('/expenses', (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(403).send('Not logged in');
  db.all('SELECT * FROM expenses WHERE user_id = ?', [userId], (err, rows) => {
    res.json(rows);
  });
});

app.post('/expenses', (req, res) => {
  const { amount, category, date, note } = req.body;
  const userId = req.session.userId;
  db.run('INSERT INTO expenses (user_id, amount, category, date, note) VALUES (?, ?, ?, ?, ?)', 
    [userId, amount, category, date, note],
    () => res.status(201).send('Expense added'));
});

app.delete('/expenses/:id', (req, res) => {
  const userId = req.session.userId;
  const id = req.params.id;
  db.run('DELETE FROM expenses WHERE id = ? AND user_id = ?', [id, userId], () => {
    res.sendStatus(200);
  });
});

app.put('/expenses/:id', (req, res) => {
  const userId = req.session.userId;
  const id = req.params.id;
  const { amount, category, date, note } = req.body;
  db.run(
    `UPDATE expenses 
     SET amount = ?, category = ?, date = ?, note = ? 
     WHERE id = ? AND user_id = ?`,
    [amount, category, date, note, id, userId],
    () => res.sendStatus(200)
  );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
