// server.js
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');

// Initialize Express app
const app = express();
app.use(express.json());

// SQLite3 Database setup
const db = new sqlite3.Database('./todo.db', (err) => {
  if (err) return console.error(err.message);
  console.log('Connected to the SQLite database.');
});

// Create users and todos tables
db.run(`CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL
)`);

db.run(`CREATE TABLE IF NOT EXISTS todos (
  id TEXT PRIMARY KEY,
  userId TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  FOREIGN KEY (userId) REFERENCES users(id)
)`);

// JWT Middleware for protected routes
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send('Token required.');

  jwt.verify(token, 'secret', (err, user) => {
    if (err) return res.status(401).send('Invalid token.');
    req.user = user;
    next();
  });
};

// Helper function to generate JWT token
const generateToken = (userId) => {
  return jwt.sign({ userId }, 'secret', { expiresIn: '1h' });
};

// User Signup
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const userId = uuidv4();

  db.run(
    'INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)',
    [userId, name, email, hashedPassword],
    (err) => {
      if (err) return res.status(500).send('Error registering user.');
      res.status(201).send({ message: 'User registered successfully.' });
    }
  );
});

// User Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(404).send('User not found.');

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).send('Incorrect password.');

    const token = generateToken(user.id);
    res.send({ token });
  });
});

// Create Todo (Protected)
app.post('/todos', authenticateToken, (req, res) => {
  const { title, description } = req.body;
  const todoId = uuidv4();

  db.run(
    'INSERT INTO todos (id, userId, title, description, status) VALUES (?, ?, ?, ?, ?)',
    [todoId, req.user.userId, title, description, 'pending'],
    (err) => {
      if (err) return res.status(500).send('Error creating task.');
      res.status(201).send({ message: 'Task created successfully.' });
    }
  );
});

// Get All Todos (Protected)
app.get('/todos', authenticateToken, (req, res) => {
  db.all('SELECT * FROM todos WHERE userId = ?', [req.user.userId], (err, rows) => {
    if (err) return res.status(500).send('Error fetching tasks.');
    res.send(rows);
  });
});

// Update Todo Status (Protected)
app.put('/todos/:id', authenticateToken, (req, res) => {
  const { status } = req.body;

  db.run(
    'UPDATE todos SET status = ? WHERE id = ? AND userId = ?',
    [status, req.params.id, req.user.userId],
    function (err) {
      if (err) return res.status(500).send('Error updating task.');
      if (this.changes === 0) return res.status(404).send('Task not found.');
      res.send({ message: 'Task updated successfully.' });
    }
  );
});

// Delete Todo (Protected)
app.delete('/todos/:id', authenticateToken, (req, res) => {
  db.run(
    'DELETE FROM todos WHERE id = ? AND userId = ?',
    [req.params.id, req.user.userId],
    function (err) {
      if (err) return res.status(500).send('Error deleting task.');
      if (this.changes === 0) return res.status(404).send('Task not found.');
      res.send({ message: 'Task deleted successfully.' });
    }
  );
});

// Profile Update (Protected)
app.put('/profile', authenticateToken, async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = password ? await bcrypt.hash(password, 10) : undefined;

  db.run(
    'UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?',
    [name, email, hashedPassword || req.user.password, req.user.userId],
    function (err) {
      if (err) return res.status(500).send('Error updating profile.');
      res.send({ message: 'Profile updated successfully.' });
    }
  );
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
