const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql');

// Initialize Express app and set up JSON body parsing
const app = express();
app.use(express.static('public'));
app.set('view engine', 'html');
app.use(express.json());

// Create MySQL connection pool
const pool = mysql.createPool({
  connectionLimit: 10,
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'jwt_gpt',
});


app.get('/register', async(req, res) => {
  res.sendFile("public/registeration.html", { root: './' })
})


// Register a new user
app.post('/register', async (req, res) => {
  const { email, password, confirmPassword } = req.body;

  // Check if the email and password fields are present
  if (!email || !password) {
    return res.status(400).send('Email and password are required');
  }

  // Check if the password and confirmation match
  if (password !== confirmPassword) {
    return res.status(400).send('Password and confirmation do not match');
  }

  // Hash the password using bcrypt
  const hashedPassword = await bcrypt.hash(password, 10);

  // Insert the user into the MySQL database
  pool.query(
    'INSERT INTO users (email, password) VALUES (?, ?)',
    [email, hashedPassword],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }

      // Generate a JWT token for the user
      const token = jwt.sign({ email }, 'secret', { expiresIn: '1h' });

      // Send the token back to the client
      res.status(200).json({ token });
      //res.send("user created !")
    }
  );
});

app.get('/login', async(req, res) => {
  res.sendFile("public/login.html", { root: './' })
})


// Authenticate a user
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Check if the email and password fields are present
  if (!email || !password) {
    return res.status(400).send('Email and password are required');
  }

  // Retrieve the user from the MySQL database
  pool.query(
    'SELECT * FROM users WHERE email = ?',
    [email],
    async (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }

      // Check if the user exists and the password matches
      if (results.length === 0 || !await bcrypt.compare(password, results[0].password)) {
        return res.status(401).send('Invalid email or password');
      }

      // Generate a JWT token for the user
      const token = jwt.sign({ email }, 'secret', { expiresIn: '1h' });

      // Send the token back to the client
      // res.sendFile("home.html", { root: './' })
      res.status(200).json({ token });
    }
  );
});


// Verify JWT tokens
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).send('Unauthorized');
  }

  jwt.verify(token, 'secret', (err, decoded) => {
    if (err) {
      console.error(err);

           return res.status(403).send('Forbidden');
   }

   req.email = decoded.email;
   next();
 });
}

// Get the user's data
app.get('/user', verifyToken, (req, res) => {
const email = req.email;
 // Retrieve the user from the MySQL database
 pool.query(
   'SELECT email FROM users WHERE email = ?',
   [email],
   (err, results) => {
     if (err) {
       console.error(err);
       return res.status(500).send('Internal Server Error');
     }

     // Send the user's email back to the client
     res.status(200).json({ email: results[0].email });
   }
 );
});

app.get('/', async (req, res) => {
    res.sendFile("public/landing.html", { root: './' })
});


app.get('/logout', (req, res) => {
  // Clear the token cookie
  res.clearCookie('token');

  // Redirect to the home page or login page
  res.redirect('/');
});

// Start the Express app
app.listen(3000, () => {
console.log('Server listening on port 3000');
});
     

