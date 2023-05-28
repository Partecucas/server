import express from 'express';
import cors from 'cors';
import { pool } from './db.js';
import { PORT } from './config.js';
import { JWT_SECRET } from './config.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const app = express();

app.use(cors());
app.use(express.json());

// Registro de usuario
app.post('/register', async (req, res) => {
  const { email, name, password, school } = req.body;
  const conn = await pool.getConnection();
  try {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const [result] = await conn.query(
      'INSERT INTO users (email, name, password, school) VALUES (?, ?, ?, ?)',
      [email, name, hashedPassword, school]
    );
    res.json({ id: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    conn.release();
  }
});

// Inicio de sesión
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const conn = await pool.getConnection();
  try {
    const [results] = await conn.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    if (results.length > 0) {
      const user = results[0];
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        // ...
        const token = jwt.sign({ userId: user.id, name: user.name , email:user.email }, JWT_SECRET, { expiresIn: '1h' });
        // ...


        // Envía el token como respuesta en un objeto JSON
        res.json({
          error: false,
          message: 'Login successful',
          user: user,
          token: token,
        });
      } else {
        res.json({
          error: true,
          message: 'Invalid credentials',
          user: null,
        });
      }
    } else {
      res.json({
        error: true,
        message: 'Invalid credentials',
        user: null,
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    conn.release();
  }
});


// Middleware para verificar el token de autenticación
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) {
    return res.sendStatus(401);
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

// Ruta protegida para el home
// ...
// Ruta protegida para el home
// Ruta protegida para el home
app.get('/home', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const conn = await pool.getConnection();
    
    const [results] = await conn.query('SELECT name FROM users WHERE id = ?', [userId]);
    conn.release();
    
    if (results.length > 0) {
      const { name } = results[0];
      
      res.json({ message: 'Welcome to the Home Page!', name });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ...





// Obtener todos los usuarios
app.get('/users', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query('SELECT * FROM users');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    conn.release();
  }
});

// Obtener un usuario por su ID
app.get('/users/:id', async (req, res) => {
  const { id } = req.params;
  const conn = await pool.getConnection();
  try {
    const [results] = await conn.query('SELECT * FROM users WHERE id = ?', [id]);
    if (results.length > 0) {
      res.json(results[0]);
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    conn.release();
  }
});

// Actualizar un usuario existente
app.put('/users/:id', async (req, res) => {
  const { id } = req.params;
  const { email, name, password, school } = req.body;
  const conn = await pool.getConnection();
  try {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const [result] = await conn.query(
      'UPDATE users SET email = ?, name = ?, password = ?, school = ? WHERE id = ?',
      [email, name, hashedPassword, school, id]
    );
    if (result.affectedRows > 0) {
      res.json({ message: 'User updated successfully' });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    conn.release();
  }
});

// Eliminar un usuario
app.delete('/users/:id', async (req, res) => {
  const { id } = req.params;
  const conn = await pool.getConnection();
  try {
    const [result] = await conn.query('DELETE FROM users WHERE id = ?', [id]);
    if (result.affectedRows > 0) {
      res.json({ message: 'User deleted successfully' });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    conn.release();
  }
});
// Logout: eliminar el token
app.post('/logout', (req, res) => {
  // Eliminar el token del almacenamiento local
  localStorage.removeItem('token');

  res.json({ message: 'Logout successful' });
});


app.listen(PORT);
console.log('Server on port', PORT);
