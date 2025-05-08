// Affiliate Link & Product Sharing Platform - Server (app.js)
// A single-file Node.js application using MySQL database

// Import required modules
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const nodemailer = require('nodemailer');

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir)
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: function (req, file, cb) {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('Only JPG, PNG and GIF files are allowed'));
    }
    cb(null, true);
  }
});

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Configure middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'affiliate-platform-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Cart count middleware
app.use(async (req, res, next) => {
  if (req.session.userId) {
    try {
      const [cartCount] = await pool.query(
        'SELECT COUNT(*) as count FROM cart_items WHERE user_id = ?',
        [req.session.userId]
      );
      res.locals.cartCount = cartCount[0].count;
    } catch (err) {
      console.error('Error fetching cart count:', err);
      res.locals.cartCount = 0;
    }
  }
  next();
});

// Set EJS as the view engine
app.set('view engine', 'ejs');

// Create MySQL connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'benixs_benix',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Configure email transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: process.env.SMTP_PORT || 587,
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Helper function to send email
async function sendEmail(to, subject, html) {
  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || '"BenixSpace" <noreply@benixspace.com>',
      to,
      subject,
      html
    });
  } catch (err) {
    console.error('Email sending error:', err);
  }
}

// Helper function to send withdrawal notification
async function sendWithdrawalNotification(user, transaction, status) {
  const statusText = {
    completed: 'processed and sent',
    failed: 'cancelled'
  }[status];

  const emailHtml = `
    <h2>Withdrawal Update</h2>
    <p>Hello ${user.username},</p>
    <p>Your withdrawal request for $${transaction.amount} has been ${statusText}.</p>
    ${status === 'failed' ? '<p>The amount has been returned to your wallet.</p>' : ''}
    ${transaction.details ? `<p>Details: ${transaction.details}</p>` : ''}
    <p>If you have any questions, please contact support.</p>
    <br>
    <p>Best regards,<br>BenixSpace Team</p>
  `;

  await sendEmail(
    user.email,
    `Withdrawal ${status === 'completed' ? 'Processed' : 'Update'}`,
    emailHtml
  );
}

// Initialize the database tables if they don't exist
async function initializeDatabase() {
  const connection = await pool.getConnection();
  try {
    // Create config table with adjusted key length and row format
    await connection.query(`
      CREATE TABLE IF NOT EXISTS config (
        id INT AUTO_INCREMENT PRIMARY KEY,
        key_name VARCHAR(191) NOT NULL UNIQUE,
        value TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ROW_FORMAT=DYNAMIC
    `);

    // Create users table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        email VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(100) NOT NULL,
        role ENUM('admin', 'merchant', 'user') DEFAULT 'user',
        wallet DECIMAL(10,2) DEFAULT 0,
        earnings DECIMAL(10,2) DEFAULT 0,
        has_lifetime_commission BOOLEAN DEFAULT FALSE,
        business_name VARCHAR(100),
        business_description TEXT,
        is_verified BOOLEAN DEFAULT FALSE,
        amount_to_pay DECIMAL(10,2) DEFAULT 0,
        paid_balance DECIMAL(10,2) DEFAULT 0,
        account_name VARCHAR(150),
        account_number VARCHAR(150),
        bank_code VARCHAR(50),
        phone_number VARCHAR(20),
        notes TEXT,
        last_login_date DATETIME,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Add last_login_date column to users table if it doesn't exist
    try {
      await connection.query(`
        ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_date DATETIME;
      `);
    } catch (err) {
      // For databases that don't support IF NOT EXISTS in ALTER TABLE
      const [columns] = await connection.query(`
        SHOW COLUMNS FROM users LIKE 'last_login_date'
      `);
      
      if (columns.length === 0) {
        await connection.query(`
          ALTER TABLE users ADD COLUMN last_login_date DATETIME;
        `);
      }
    }
   
    // Check if we need to rename merchant_balance to amount_to_pay
    try {
      const [columns] = await connection.query(`
        SHOW COLUMNS FROM users LIKE 'merchant_balance'
      `);
      
      if (columns.length > 0) {
        // Rename merchant_balance to amount_to_pay
        await connection.query(`
          ALTER TABLE users 
          CHANGE merchant_balance amount_to_pay DECIMAL(10,2) DEFAULT 0
        `);
        
        console.log('Renamed merchant_balance to amount_to_pay');
      }
      
      // Add paid_balance column if it doesn't exist
      const [paidBalanceColumn] = await connection.query(`
        SHOW COLUMNS FROM users LIKE 'paid_balance'
      `);
      
      if (paidBalanceColumn.length === 0) {
        await connection.query(`
          ALTER TABLE users 
          ADD COLUMN paid_balance DECIMAL(10,2) DEFAULT 0 AFTER amount_to_pay
        `);
        
        console.log('Added paid_balance column');
      }
    } catch (err) {
      console.error('Error updating users table schema:', err);
    }

    // Create links table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS links (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(150) NOT NULL,
        description TEXT,
        merchant_id INT NOT NULL,
        type ENUM('product', 'link', 'youtube') NOT NULL,
        url TEXT NOT NULL,
        image_url TEXT,
        price DECIMAL(10,2),
        category VARCHAR(150),
        click_target INT NOT NULL,
        cost_per_click DECIMAL(10,2) NOT NULL,
        clicks_count INT DEFAULT 0,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (merchant_id) REFERENCES users(id)
      )
    `);

// Update precision for existing columns if the table already exists
try {
  await connection.query(`
    ALTER TABLE users 
    MODIFY wallet DECIMAL(10,4) DEFAULT 0.0000,
    MODIFY earnings DECIMAL(10,4) DEFAULT 0.0000,
    MODIFY amount_to_pay DECIMAL(10,4) DEFAULT 0.0000,
    MODIFY paid_balance DECIMAL(10,4) DEFAULT 0.0000
  `);
} catch (err) {
  console.error('Error updating users decimal precision:', err);
}

// Also update other tables with monetary values
try {
  await connection.query(`
    ALTER TABLE shared_links 
    MODIFY earnings DECIMAL(10,4) DEFAULT 0.0000
  `);
} catch (err) {
  console.error('Error updating shared_links decimal precision:', err);
}

try {
  await connection.query(`
    ALTER TABLE transactions 
    MODIFY amount DECIMAL(10,4) NOT NULL
  `);
} catch (err) {
  console.error('Error updating transactions decimal precision:', err);
}

try {
  await connection.query(`
    ALTER TABLE links 
    MODIFY cost_per_click DECIMAL(10,4) NOT NULL
  `);
} catch (err) {
  console.error('Error updating links decimal precision:', err);
}

try {
  await connection.query(`
    ALTER TABLE order_items 
    MODIFY commission_earned DECIMAL(10,4) NOT NULL
  `);
} catch (err) {
  console.error('Error updating order_items decimal precision:', err);
}


    // Create shared_links table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS shared_links (
        id INT AUTO_INCREMENT PRIMARY KEY,
        link_id INT NOT NULL,
        user_id INT NOT NULL,
        share_code VARCHAR(150) NOT NULL UNIQUE,
        clicks INT DEFAULT 0,
        earnings DECIMAL(10,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (link_id) REFERENCES links(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    // Create clicks table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS clicks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        shared_link_id INT NOT NULL,
        ip_address VARCHAR(50),
        device_info TEXT,
        referrer TEXT,
        is_counted BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (shared_link_id) REFERENCES shared_links(id)
      )
    `);

    // Create transactions table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        type ENUM('deposit', 'withdrawal', 'commission', 'payment', 'upgrade') NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
        reference VARCHAR(150),
        details TEXT,
        notes TEXT,
        gateway VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    // Create products table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        merchant_id INT NOT NULL,
        name VARCHAR(150) NOT NULL,
        description TEXT,
        price DECIMAL(10,2) NOT NULL,
        stock INT NOT NULL DEFAULT 0,
        image_url TEXT,
        category VARCHAR(150),
        commission_rate DECIMAL(5,2) NOT NULL DEFAULT 5.00,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (merchant_id) REFERENCES users(id)
      )
    `);

    // Create cart table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS cart_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        product_id INT NOT NULL,
        quantity INT NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (product_id) REFERENCES products(id)
      )
    `);

    // Create orders table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        total_amount DECIMAL(10,2) NOT NULL,
        status ENUM('pending', 'processing', 'shipped', 'delivered', 'cancelled') DEFAULT 'pending',
        shipping_address TEXT NOT NULL,
        phone_number VARCHAR(20) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    // Create order items table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS order_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_id INT NOT NULL,
        product_id INT NOT NULL,
        quantity INT NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        commission_earned DECIMAL(10,2) NOT NULL,
        referrer_id INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (order_id) REFERENCES orders(id),
        FOREIGN KEY (product_id) REFERENCES products(id),
        FOREIGN KEY (referrer_id) REFERENCES users(id)
      )
    `);

    // Insert default config values
    const configValues = [
      ['commission_rate', '5', 'Default commission percentage for users'],
      ['cost_per_click', '0.0050', 'Default cost per click for merchants'],
      ['lifetime_commission_fee', '10', 'Fee for lifetime commission upgrade'],
      ['merchant_monthly_fee', '20', 'Monthly subscription fee for merchants'],
      ['min_payout', '10', 'Minimum amount required for payout'],
      ['min_deposit', '1', 'Minimum deposit amount for merchants'],
      ['payout_cycle', '30', 'Number of days between automatic payouts'],
      ['enable_youtube_embedding', 'true', 'Whether to allow YouTube video embedding'],
      ['umvapay_public_key', '', 'Umva Pay public key'],
      ['umvapay_secret_key', '', 'Umva Pay secret key for transaction verification'],
      ['umvapay_mode', 'test', 'Umva Pay mode (test/live)'],
      ['umvapay_site_logo', '', 'Umva Pay site logo URL'],
      ['manual_payment_instructions', 'Please transfer the amount to our account and upload a screenshot/receipt as proof of payment.', 'Instructions for manual payment processing'],
      ['manual_payment_bank_name', '', 'Bank name for manual payments'],
      ['manual_payment_account_name', '', 'Account name for manual payments'],
      ['manual_payment_account_number', '', 'Account number for manual payments'],
      ['manual_payment_swift_code', '', 'SWIFT/BIC code for international transfers (optional)']
    ];

    for (const [key, value, description] of configValues) {
      await connection.query(
        'INSERT IGNORE INTO config (key_name, value, description) VALUES (?, ?, ?)',
        [key, value, description]
      );
    }

    // Create admin user if doesn't exist
    const adminExists = await connection.query(
      'SELECT COUNT(*) as count FROM users WHERE role = ?', 
      ['admin']
    );
    
    if (adminExists[0][0].count === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await connection.query(
        'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
        ['admin', 'admin@example.com', hashedPassword, 'admin']
      );
    }

    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Error initializing database:', err);
  } finally {
    connection.release();
  }
}

// Helper functions
async function getConfig(key) {
  const [rows] = await pool.query('SELECT value FROM config WHERE key_name = ?', [key]);
  return rows.length > 0 ? rows[0].value : null;
}

async function updateConfig(key, value) {
  await pool.query('UPDATE config SET value = ? WHERE key_name = ?', [value, key]);
}

// Authentication middleware
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
}

function isAdmin(req, res, next) {
  if (req.session.role === 'admin') {
    return next();
  }
  res.status(403).render('error', { message: 'Access denied. Admin privileges required.' });
}

function isMerchant(req, res, next) {
  if (req.session.role === 'merchant' || req.session.role === 'admin') {
    return next();
  }
  res.status(403).render('error', { message: 'Access denied. Merchant privileges required.' });
}

// =============== ROUTES ===============

// Home route
// app.get('/', async (req, res) => {
//   try {
//     let links = [];
//     if (req.session.userId) {
//       // Fetch active links
//       const [rows] = await pool.query(`
//         SELECT l.*, u.username as merchant_name, u.business_name
//         FROM links l
//         JOIN users u ON l.merchant_id = u.id
//         WHERE l.is_active = true
//         ORDER BY l.created_at DESC
//         LIMIT 20
//       `);
//       links = rows;
//     }
    
//     res.render('index', { 
//       user: req.session.userId ? {
//         id: req.session.userId,
//         username: req.session.username,
//         role: req.session.role
//       } : null,
//       links: links
//     });
//   } catch (err) {
//     console.error('Error fetching home data:', err);
//     res.status(500).render('error', { message: 'Server error. Please try again later.' });
//   }
// });

// Home route
// Homepage route
app.get('/', async (req, res) => {
  try {
    // Fetch real statistics from database
    const [userCountResult] = await pool.query('SELECT COUNT(*) as count FROM users WHERE role != "admin"');
    const [clickCountResult] = await pool.query('SELECT COUNT(*) as count FROM clicks');
    const [linkCountResult] = await pool.query('SELECT COUNT(*) as count FROM links WHERE is_active = true');
    const [earningsResult] = await pool.query('SELECT SUM(earnings) as total FROM users');
    
    // Get featured merchants (limit to 3)
    const [merchants] = await pool.query(`
      SELECT u.*, COUNT(p.id) as product_count
      FROM users u 
      LEFT JOIN links p ON u.id = p.merchant_id
      WHERE u.role = 'merchant' AND u.is_verified = true
      GROUP BY u.id
      ORDER BY product_count DESC
      LIMIT 3
    `);
    
    // Simulated testimonials - in production you would fetch these from a testimonials table
    // This is a placeholder until you create a testimonials table
    const testimonials = [];
    
    // Create the stats object
    const stats = {
      userCount: userCountResult[0].count,
      clickCount: clickCountResult[0].count,
      linkCount: linkCountResult[0].count,
      totalEarnings: earningsResult[0].total || 0
    };
    
    // If user is logged in, get available links for them to share
    let links = [];
    if (req.session.userId) {
      [links] = await pool.query(`
        SELECT l.*, u.username as merchant_name, u.business_name
        FROM links l
        JOIN users u ON l.merchant_id = u.id
        WHERE l.is_active = true
        ORDER BY l.clicks_count DESC
        LIMIT 12
      `);
    }
    
    res.render('index', {
      user: req.session.userId ? {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      } : null,
      links,
      stats,
      merchants,
      testimonials
    });
  } catch (err) {
    console.error('Homepage error:', err);
    res.render('index', { user: req.session.userId ? {
      id: req.session.userId,
      username: req.session.username,
      role: req.session.role
    } : null });
  }
});

// Shop redirect route
app.get('/shop', (req, res) => {
  res.redirect('/user/products');
});

// Products route
app.get('/user/products', async (req, res) => {
  try {
    // Get all active products with merchant info
    const [products] = await pool.query(`
      SELECT p.*, u.username as merchant_name 
      FROM products p
      JOIN users u ON p.merchant_id = u.id
      WHERE p.is_active = true
      ORDER BY p.created_at DESC
    `);

    // Get all unique categories
    const [categories] = await pool.query('SELECT DISTINCT category FROM products WHERE category IS NOT NULL');
    const categoryList = categories.map(c => c.category);

    // Get cart count if user is logged in
    let cartCount = 0;
    if (req.session.userId) {
      const [cartItems] = await pool.query('SELECT COUNT(*) as count FROM cart_items WHERE user_id = ?', [req.session.userId]);
      cartCount = cartItems[0].count;
    }

    res.render('user/products', { 
      products,
      categories: categoryList,
      cartCount,
      user: req.session.userId ? {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      } : null
    });
  } catch (err) {
    console.error('Products page error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});
// Auth routes
app.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render('auth', { page: 'login', error: null });
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.render('auth', { page: 'login', error: 'Invalid email or password' });
    }
    
    const user = users[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.render('auth', { page: 'login', error: 'Invalid email or password' });
    }
    
    // Set session
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;

    // Handle login bonus
    const now = new Date();
    const lastLoginDate = user.last_login_date;
    
    try {
      // Handle login bonus
if (!lastLoginDate || new Date(lastLoginDate).toDateString() !== now.toDateString()) {
  // Give login bonus and update login date
  await pool.query(
    `UPDATE users SET 
     earnings = earnings + 0.0100, 
     wallet = wallet + 0.0100,
     last_login_date = NOW() 
     WHERE id = ?`, 
    [user.id]
  );
}
    } catch (loginBonusError) {
      console.error('Login bonus error:', loginBonusError);
      // Continue despite login bonus error
    }
    
    return res.redirect('/dashboard');
  } catch (err) {
    console.error('Login error:', err);
    return res.render('auth', { page: 'login', error: 'Server error. Please try again.' });
  }
});

app.post('/profile/update', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const {
      username,
      email,
      current_password,
      new_password,
      business_name,
      business_description,
      account_name,
      account_number,
      bank_code
    } = req.body;

    // Check if username or email already exists
    const [existingUsers] = await pool.query(
      'SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?',
      [username, email, userId]
    );

    if (existingUsers.length > 0) {
      const [user] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
      return res.render('user/profile', {
        user: user[0],
        error: 'Username or email already in use'
      });
    }

    // Update basic info
    await pool.query(`
      UPDATE users 
      SET username = ?, 
          email = ?,
          business_name = ?,
          business_description = ?,
          account_name = ?,
          account_number = ?,
          bank_code = ?
      WHERE id = ?
    `, [
      username,
      email,
      business_name || null,
      business_description || null,
      account_name,
      account_number,
      bank_code,
      userId
    ]);

    // Update password if provided
    if (current_password && new_password) {
      const [user] = await pool.query('SELECT password FROM users WHERE id = ?', [userId]);
      const passwordMatch = await bcrypt.compare(current_password, user[0].password);

      if (!passwordMatch) {
        return res.render('user/profile', {
          user: { ...req.body, id: userId },
          error: 'Current password is incorrect'
        });
      }

      const hashedPassword = await bcrypt.hash(new_password, 10);
      await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId]);
    }

    // Get updated user data
    const [updatedUser] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    
    res.render('user/profile', {
      user: updatedUser[0],
      success: 'Profile updated successfully'
    });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

app.post('/register', async (req, res) => {
  try {
    const { username, email, password, confirmPassword, role, business_name, business_description } = req.body;
    
    // Basic validation
    if (password !== confirmPassword) {
      return res.render('auth', { page: 'register', error: 'Passwords do not match' });
    }
    
    // Validate role
    if (!['user', 'merchant'].includes(role)) {
      return res.render('auth', { page: 'register', error: 'Invalid role selected' });
    }
    
    // Additional validation for merchants
    if (role === 'merchant' && (!business_name || !business_description)) {
      return res.render('auth', { 
        page: 'register', 
        error: 'Business name and description are required for merchant accounts' 
      });
    }
    
    // Check if user exists
    const [existingUsers] = await pool.query(
      'SELECT * FROM users WHERE username = ? OR email = ?', 
      [username, email]
    );
    
    if (existingUsers.length > 0) {
      return res.render('auth', { 
        page: 'register', 
        error: 'Username or email already in use' 
      });
    }
    
    // Create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (username, email, password, role, business_name, business_description) VALUES (?, ?, ?, ?, ?, ?)',
      [username, email, hashedPassword, role, business_name || null, business_description || null]
    );
    
    // Set session
    req.session.userId = result.insertId;
    req.session.username = username;
    req.session.role = role;
    
    res.redirect('/dashboard');
  } catch (err) {
    console.error('Registration error:', err);
    res.render('auth', { page: 'register', error: 'Server error. Please try again.' });
  }
});

app.get('/register', (req, res) => {
  try{

    return res.render('auth', { page: 'register', error: null });
  

} catch (err) {
  console.error('Failed to load register page:', err);
  return res.status(500).render('error', { message: 'Server error. Please try again later.' });
}
});



// app.post('/register', async (req, res) => {
//   try {
//     const { username, email, password, confirmPassword } = req.body;
    
//     // Basic validation
//     if (password !== confirmPassword) {
//       return res.render('auth', { page: 'register', error: 'Passwords do not match' });
//     }
    
//     // Check if user exists
//     const [existingUsers] = await pool.query(
//       'SELECT * FROM users WHERE username = ? OR email = ?', 
//       [username, email]
//     );
    
//     if (existingUsers.length > 0) {
//       return res.render('auth', { 
//         page: 'register', 
//         error: 'Username or email already in use' 
//       });
//     }
    
//     // Create user
//     const hashedPassword = await bcrypt.hash(password, 10);
//     const [result] = await pool.query(
//       'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
//       [username, email, hashedPassword]
//     );
    
//     // Set session
//     req.session.userId = result.insertId;
//     req.session.username = username;
//     req.session.role = 'user';
    
//     res.redirect('/dashboard');
//   } catch (err) {
//     console.error('Registration error:', err);
//     res.render('auth', { page: 'register', error: 'Server error. Please try again.' });
//   }
// });

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Dashboard routes
app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    const user = users[0];
    
    let data = {
      user: user,
      stats: {}
    };
    
    if (user.role === 'admin') {
      // Admin dashboard data
      const [userCount] = await pool.query('SELECT COUNT(*) as count FROM users');
      const [merchantCount] = await pool.query('SELECT COUNT(*) as count FROM users WHERE role = ?', ['merchant']);
      const [linkCount] = await pool.query('SELECT COUNT(*) as count FROM links');
      const [clickCount] = await pool.query('SELECT COUNT(*) as count FROM clicks');

      // In the dashboard route, replace the existing gatewayStats query with this:
const [gatewayStats] = await pool.query(`
  SELECT 
    COALESCE(SUM(CASE 
      WHEN details LIKE '%via Umva Pay%' AND status = 'completed' 
      THEN amount 
    END), 0) as umvapayVolume,
    
    COUNT(CASE 
      WHEN details LIKE '%via Umva Pay%' AND status = 'completed' 
      THEN 1 
    END) as umvapayCount,
    
    COALESCE(SUM(CASE 
      WHEN details LIKE '%via Umva Pay%' AND type = 'upgrade' AND status = 'completed' 
      THEN amount 
    END), 0) as umvapayUpgrades,
    
    COALESCE(SUM(CASE 
      WHEN details LIKE '%via Umva Pay%' AND type = 'withdrawal' AND status = 'completed' 
      THEN amount 
    END), 0) as umvapayWithdrawals
  FROM transactions
  WHERE details LIKE '%via Umva Pay%'
`);

      // Get recent gateway transactions
      const [recentGatewayTransactions] = await pool.query(`
        SELECT t.*, u.username 
        FROM transactions t 
        JOIN users u ON t.user_id = u.id 
        WHERE t.details LIKE '%via Umva Pay%'
        ORDER BY t.created_at DESC 
        LIMIT 10
      `);
      
      data.stats = {
        userCount: userCount[0].count,
        merchantCount: merchantCount[0].count,
        linkCount: linkCount[0].count,
        clickCount: clickCount[0].count,
        recentTransactions: recentGatewayTransactions,
        ...gatewayStats[0],
        recentGatewayTransactions
      };
      
      // Get config settings
      const [configSettings] = await pool.query('SELECT * FROM config');
      data.config = configSettings;
    } 
    else if (user.role === 'merchant') {
      // Merchant dashboard data
      const [links] = await pool.query('SELECT * FROM links WHERE merchant_id = ?', [userId]);
      const [totalClicks] = await pool.query(`
        SELECT COUNT(*) as count FROM clicks c
        JOIN shared_links sl ON c.shared_link_id = sl.id
        JOIN links l ON sl.link_id = l.id
        WHERE l.merchant_id = ?
      `, [userId]);
      
      data.stats = {
        linkCount: links.length,
        totalClicks: totalClicks[0].count,
        amountToPay: parseFloat(user.amount_to_pay || 0).toFixed(2),
        paidBalance: parseFloat(user.paid_balance || 0).toFixed(2),
        links: links
      };
    } 
    else {
      // Regular user dashboard data
      const [sharedLinks] = await pool.query(`
        SELECT sl.*, l.title, l.type, l.url, l.image_url 
        FROM shared_links sl
        JOIN links l ON sl.link_id = l.id
        WHERE sl.user_id = ?
      `, [userId]);
      
      const [totalClicks] = await pool.query(`
        SELECT COUNT(*) as count FROM clicks c
        JOIN shared_links sl ON c.shared_link_id = sl.id
        WHERE sl.user_id = ?
      `, [userId]);
      
      data.stats = {
        sharedLinkCount: sharedLinks.length,
        totalClicks: totalClicks[0].count,
        totalEarnings: user.earnings,
        sharedLinks: sharedLinks
      };
      
      // Fetch available links to share
      const [availableLinks] = await pool.query(`
        SELECT l.*, u.username as merchant_name, u.business_name
        FROM links l
        JOIN users u ON l.merchant_id = u.id
        WHERE l.is_active = true
        ORDER BY l.created_at DESC
        LIMIT 20
      `);
      
      data.availableLinks = availableLinks;
    }
    
    res.render('dashboard', data);
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Wallet route
app.get('/wallet', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    const user = users[0];

    // Get minimum payout amount from config
    const minPayout = await getConfig('min_payout');
    
    // Get manual payment instructions
    const manualInstructions = await getConfig('manual_payment_instructions');

    // Get user's transactions
    const [transactions] = await pool.query(`
      SELECT * FROM transactions 
      WHERE user_id = ? AND (type = 'commission' OR type = 'withdrawal')
      ORDER BY created_at DESC
    `, [userId]);

    res.render('user/wallet', { 
      user,
      transactions,
      minPayout: parseFloat(minPayout),
      manualInstructions: manualInstructions || 'Please transfer the amount to our account and upload a screenshot/receipt as proof of payment.'
    });
  } catch (err) {
    console.error('Wallet page error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Profile routes
app.get('/profile', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    const user = users[0];

    // Initialize default stats
    const stats = {
      totalLinks: 0,
      totalClicks: 0,
      totalEarnings: parseFloat(user.earnings || 0)
    };

    if (user.role === 'merchant') {
      const [linkCount] = await pool.query('SELECT COUNT(*) as count FROM links WHERE merchant_id = ?', [userId]);
      const [clickCount] = await pool.query(`
        SELECT COUNT(*) as count FROM clicks c
        JOIN shared_links sl ON c.shared_link_id = sl.id
        JOIN links l ON sl.link_id = l.id
        WHERE l.merchant_id = ?
      `, [userId]);

      stats.totalLinks = linkCount[0].count;
      stats.totalClicks = clickCount[0].count;
    } else {
      const [linkCount] = await pool.query('SELECT COUNT(*) as count FROM shared_links WHERE user_id = ?', [userId]);
      const [clickCount] = await pool.query(`
        SELECT COUNT(*) as count FROM clicks c
        JOIN shared_links sl ON c.shared_link_id = sl.id
        WHERE sl.user_id = ?
      `, [userId]);

      stats.totalLinks = linkCount[0].count;
      stats.totalClicks = clickCount[0].count;
    }

    return res.render('user/profile', { 
      user, 
      stats,
      success: req.query.success,
      error: req.query.error 
    });
  } catch (err) {
    console.error('Profile page error:', err);
    return res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Merchant link management routes
// Fix for the "no links showing" issue in the merchant links route
app.get('/merchant/links', isAuthenticated, isMerchant, async (req, res) => {
  try {
    const userId = req.session.userId;
    
    // Get all links for this merchant with COALESCE to handle NULLs
    const [links] = await pool.query(`
      SELECT l.*, 
             COUNT(DISTINCT sl.id) as share_count,
             COALESCE(SUM(sl.clicks), 0) as total_clicks
      FROM links l
      LEFT JOIN shared_links sl ON l.id = sl.link_id
      WHERE l.merchant_id = ?
      GROUP BY l.id
      ORDER BY l.created_at DESC
    `, [userId]);
    
    console.log('Merchant links found:', links.length);
    
    res.render('merchant/links', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      links: links,
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Merchant links error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Fix for the "Failed to create link" issue
app.post('/merchant/links/create', isAuthenticated, isMerchant, upload.single('image'), async (req, res) => {
  try {
    const userId = req.session.userId;
    const {
      title,
      description,
      type,
      url,
      category,
      click_target,
      cost_per_click,
      price
    } = req.body;
    
    // Validate required fields
    if (!title || !type || !url || !click_target) {
      return res.redirect('/merchant/links/create?error=Missing required fields');
    }
    
    // Get the file path if an image was uploaded
    let imageUrl = null;
    if (req.file) {
      imageUrl = `/uploads/${req.file.filename}`;
    }
    
    // Ensure cost_per_click is a valid number
    let linkCostPerClick;
    if (!cost_per_click || isNaN(parseFloat(cost_per_click))) {
      // If not provided or invalid, get default from config
      linkCostPerClick = await getConfig('cost_per_click');
    } else {
      linkCostPerClick = cost_per_click;
    }
    
    // Convert to float to ensure it's a valid number
    const costPerClickValue = parseFloat(linkCostPerClick);
    
    // Insert the new link
    await pool.query(`
      INSERT INTO links (
        title, 
        description, 
        merchant_id, 
        type, 
        url, 
        image_url, 
        category,
        price, 
        click_target, 
        cost_per_click,
        is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, true)
    `, [
      title,
      description || null,
      userId,
      type,
      url,
      imageUrl,
      category || null,
      price || null,
      parseInt(click_target),
      costPerClickValue // This will now always be a valid number
    ]);
    
    res.redirect('/merchant/links?success=Link created successfully');
  } catch (err) {
    console.error('Link creation error:', err);
    res.redirect('/merchant/links/create?error=Failed to create link. Please try again.');
  }
});

app.get('/merchant/links/create', isAuthenticated, isMerchant, async (req, res) => {
  try {
    // Get cost per click from config
    const costPerClick = await getConfig('cost_per_click');
    
    res.render('merchant/link-form', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      link: null, // null means new link
      costPerClick: parseFloat(costPerClick),
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Link form error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

app.post('/merchant/links/create', isAuthenticated, isMerchant, upload.single('image'), async (req, res) => {
  try {
    const userId = req.session.userId;
    const {
      title,
      description,
      type,
      url,
      category,
      click_target,
      cost_per_click,
      price // Include price field
    } = req.body;
    
    // Validate required fields
    if (!title || !type || !url || !click_target) {
      return res.redirect('/merchant/links/create?error=Missing required fields');
    }
    
    // Get the file path if an image was uploaded
    let imageUrl = null;
    if (req.file) {
      imageUrl = `/uploads/${req.file.filename}`;
    }
    
    // Insert the new link
    await pool.query(`
      INSERT INTO links (
        title, 
        description, 
        merchant_id, 
        type, 
        url, 
        image_url, 
        category,
        price, 
        click_target, 
        cost_per_click,
        is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, true)
    `, [
      title,
      description || null,
      userId,
      type,
      url,
      imageUrl,
      category || null,
      price || null,
      parseFloat(click_target),
      parseFloat(cost_per_click)
    ]);
    
    res.redirect('/merchant/links?success=Link created successfully');
  } catch (err) {
    console.error('Link creation error:', err);
    res.redirect('/merchant/links/create?error=Failed to create link. Please try again.');
  }
});
app.get('/merchant/links/:id/edit', isAuthenticated, isMerchant, async (req, res) => {
  try {
    const linkId = req.params.id;
    const userId = req.session.userId;
    
    // Get link details, ensuring it belongs to this merchant
    const [links] = await pool.query(`
      SELECT * FROM links
      WHERE id = ? AND merchant_id = ?
    `, [linkId, userId]);
    
    if (links.length === 0) {
      return res.status(404).render('error', { message: 'Link not found or you don\'t have permission to edit it.' });
    }
    
    // Get cost per click from config
    const costPerClick = await getConfig('cost_per_click');
    
    res.render('merchant/link-form', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      link: links[0],
      costPerClick: parseFloat(costPerClick),
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Edit link form error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

app.post('/merchant/links/:id/edit', isAuthenticated, isMerchant, upload.single('image'), async (req, res) => {
  try {
    const linkId = req.params.id;
    const userId = req.session.userId;
    const {
      title,
      description,
      type,
      url,
      category,
      click_target,
      cost_per_click,
      is_active
    } = req.body;
    
    // Verify link belongs to this merchant
    const [links] = await pool.query(`
      SELECT l.*
      FROM links l
      WHERE l.id = ? AND l.merchant_id = ?
    `, [linkId, userId]);
    
    if (links.length === 0) {
      return res.status(404).render('error', { message: 'Link not found or you don\'t have permission to edit it.' });
    }
    
    // Get the file path if a new image was uploaded
    let imageUrl = links[0].image_url;
    if (req.file) {
      imageUrl = `/uploads/${req.file.filename}`;
      
      // Delete old image if it exists
      if (links[0].image_url) {
        const oldImagePath = path.join(__dirname, 'public', links[0].image_url);
        if (fs.existsSync(oldImagePath)) {
          fs.unlinkSync(oldImagePath);
        }
      }
    }
    
    // Update the link
    await pool.query(`
      UPDATE links
      SET title = ?,
          description = ?,
          type = ?,
          url = ?,
          image_url = ?,
          category = ?,
          click_target = ?,
          cost_per_click = ?,
          is_active = ?
      WHERE id = ? AND merchant_id = ?
    `, [
      title,
      description,
      type,
      url,
      imageUrl,
      category,
      click_target,
      cost_per_click,
      is_active ? 1 : 0,
      linkId,
      userId
    ]);
    
    res.redirect(`/merchant/links?success=Link updated successfully`);
  } catch (err) {
    console.error('Link update error:', err);
    res.redirect(`/merchant/links/${req.params.id}/edit?error=Failed to update link. Please try again.`);
  }
});

// Route to view a specific merchant link
app.get('/merchant/links/:id', isAuthenticated, isMerchant, async (req, res) => {
  try {
    const linkId = req.params.id;
    const userId = req.session.userId;
    
    // Get link details, ensuring it belongs to this merchant
    const [links] = await pool.query(`
      SELECT l.*
      FROM links l
      WHERE l.id = ? AND l.merchant_id = ?
    `, [linkId, userId]);
    
    if (links.length === 0) {
      return res.status(404).render('error', { message: 'Link not found or you don\'t have permission to view it.' });
    }
    
    const link = links[0];
    
    // Get analytics data for this link with corrected queries
    const [analytics] = await pool.query(`
      SELECT 
        COUNT(DISTINCT sl.id) as total_shares,
        SUM(sl.clicks) as total_clicks,
        COALESCE(SUM(sl.earnings), 0) as total_earnings
      FROM links l
      LEFT JOIN shared_links sl ON l.id = sl.link_id
      WHERE l.id = ?
      GROUP BY l.id
    `, [linkId]);
    
    // If no analytics records were found, initialize with zeros
    const analyticsData = analytics.length > 0 ? analytics[0] : { 
      total_shares: 0, 
      total_clicks: 0, 
      total_earnings: 0 
    };
    
    // Get users who shared this link with correct click count calculation
    const [shares] = await pool.query(`
      SELECT 
        sl.*, 
        u.username, 
        sl.clicks as click_count,
        COALESCE(sl.earnings, 0) as user_earnings
      FROM shared_links sl
      JOIN users u ON sl.user_id = u.id
      WHERE sl.link_id = ?
      ORDER BY sl.clicks DESC
    `, [linkId]);
    
    res.render('merchant/link-details', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      link: link,
      analytics: analyticsData,
      shares: shares,
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Merchant link details error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Route for handling shared links with shortcodes
// app.get('/l/:code', async (req, res) => {
//   try {
//     const shareCode = req.params.code;
    
//     // Find the shared link with this code
//     const [sharedLinks] = await pool.query(`
//       SELECT sl.*, l.url, l.title, l.description, l.type, l.merchant_id, l.image_url, l.price
//       FROM shared_links sl
//       JOIN links l ON sl.link_id = l.id
//       WHERE sl.share_code = ?
//     `, [shareCode]);
    
//     if (sharedLinks.length === 0) {
//       return res.status(404).render('error', { message: 'Link not found or it may have been removed.' });
//     }
    
//     const sharedLink = sharedLinks[0];
    
//     // Record the click
//     const ip = req.ip || req.connection.remoteAddress;
//     const userAgent = req.headers['user-agent'];
//     const referrer = req.headers.referer || req.headers.referrer || '';
    
//     // Insert click record
//     const [clickResult] = await pool.query(`
//       INSERT INTO clicks (shared_link_id, ip_address, device_info, referrer, is_counted)
//       VALUES (?, ?, ?, ?, true)
//     `, [sharedLink.id, ip, userAgent, referrer]);
    
//     // Update click count in shared_links table
//     await pool.query(`
//       UPDATE shared_links SET clicks = clicks + 1 WHERE id = ?
//     `, [sharedLink.id]);
    
//     // Update total clicks in links table
//     await pool.query(`
//       UPDATE links SET clicks_count = clicks_count + 1 WHERE id = ?
//     `, [sharedLink.link_id]);
    
//     // Calculate and add commission for the sharer
//     const [links] = await pool.query('SELECT * FROM links WHERE id = ?', [sharedLink.link_id]);
//     const link = links[0];
    
//     // Calculate and add commission for the sharer
// const costPerClick = parseFloat(link.cost_per_click) || 0.0050;
// const commissionRate = await getConfig('commission_rate');
// const commission = parseFloat((costPerClick * (parseFloat(commissionRate) / 100)).toFixed(4));

// // Update earnings in shared_links
// await pool.query(`
//   UPDATE shared_links SET earnings = earnings + ? WHERE id = ?
// `, [commission, sharedLink.id]);

// // Update user earnings
// await pool.query(`
//   UPDATE users SET earnings = COALESCE(earnings, 0) + ?, wallet = COALESCE(wallet, 0) + ? WHERE id = ?
// `, [commission, commission, sharedLink.user_id]); 
//     // Record transaction
//     await pool.query(`
//       INSERT INTO transactions (user_id, type, amount, status, details)
//       VALUES (?, 'commission', ?, 'completed', ?)
//     `, [
//       sharedLink.user_id,
//       commission,
//       `Commission for click on ${link.title}`
//     ]);
    
//     // Increment merchant's amount to pay
//     await pool.query(`
//       UPDATE users SET amount_to_pay = COALESCE(amount_to_pay, 0) + ? WHERE id = ?
//     `, [costPerClick, link.merchant_id]);
    
//     // Redirect to the destination URL
//     if (sharedLink.type === 'product') {
//       return res.redirect(`/products/${sharedLink.link_id}?ref=${sharedLink.share_code}`);
//     } else {
//       return res.redirect(sharedLink.url);
//     }
//   } catch (err) {
//     console.error('Shared link error:', err);
//     return res.status(500).render('error', { message: 'Server error. Please try again later.' });
//   }
// });
// Route for handling shared links with shortcodes
app.get('/l/:code', async (req, res) => {
  try {
    const shareCode = req.params.code;
    
    // Find the shared link with this code
    const [sharedLinks] = await pool.query(`
      SELECT sl.*, l.url, l.title, l.description, l.type, l.merchant_id, l.image_url, l.price
      FROM shared_links sl
      JOIN links l ON sl.link_id = l.id
      WHERE sl.share_code = ?
    `, [shareCode]);
    
    if (sharedLinks.length === 0) {
      return res.status(404).render('error', { message: 'Link not found or it may have been removed.' });
    }
    
    const sharedLink = sharedLinks[0];
    
    // Record the click
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    const referrer = req.headers.referer || req.headers.referrer || '';
    
    // Check if this IP has clicked this shared link recently (within 10 minutes)
    const [recentClicks] = await pool.query(`
      SELECT created_at FROM clicks 
      WHERE shared_link_id = ? AND ip_address = ?
      ORDER BY created_at DESC LIMIT 1
    `, [sharedLink.id, ip]);
    
    // Determine if we should count this click
    let countClick = true;
    
    if (recentClicks.length > 0) {
      const lastClickTime = new Date(recentClicks[0].created_at);
      const currentTime = new Date();
      const minutesDifference = (currentTime - lastClickTime) / (1000 * 60);
      
      // Only count clicks from the same IP if more than 10 minutes have passed
      countClick = minutesDifference >= 10;
    }
    
    // Insert click record
    await pool.query(`
      INSERT INTO clicks (shared_link_id, ip_address, device_info, referrer, is_counted)
      VALUES (?, ?, ?, ?, ?)
    `, [sharedLink.id, ip, userAgent, referrer, countClick]);
    
    // Only update stats and pay commission if we're counting this click
    if (countClick) {
      // Update click count in shared_links table
      await pool.query(`
        UPDATE shared_links SET clicks = clicks + 1 WHERE id = ?
      `, [sharedLink.id]);
      
      // Update total clicks in links table
      await pool.query(`
        UPDATE links SET clicks_count = clicks_count + 1 WHERE id = ?
      `, [sharedLink.link_id]);
      
      // Calculate and add commission for the sharer
      const [links] = await pool.query('SELECT * FROM links WHERE id = ?', [sharedLink.link_id]);
      const link = links[0];
      
      const costPerClick = parseFloat(link.cost_per_click) || 0.0050;
      const commissionRate = await getConfig('commission_rate');
      const commission = parseFloat((costPerClick * (parseFloat(commissionRate) / 100)).toFixed(4));
      
      // Update earnings in shared_links
      await pool.query(`
        UPDATE shared_links SET earnings = earnings + ? WHERE id = ?
      `, [commission, sharedLink.id]);
      
      // Update user earnings
      await pool.query(`
        UPDATE users SET earnings = COALESCE(earnings, 0) + ?, wallet = COALESCE(wallet, 0) + ? WHERE id = ?
      `, [commission, commission, sharedLink.user_id]);
      
      // Record transaction
      await pool.query(`
        INSERT INTO transactions (user_id, type, amount, status, details)
        VALUES (?, 'commission', ?, 'completed', ?)
      `, [
        sharedLink.user_id,
        commission,
        `Commission for click on ${link.title}`
      ]);
      
      // Increment merchant's amount to pay
      await pool.query(`
        UPDATE users SET amount_to_pay = COALESCE(amount_to_pay, 0) + ? WHERE id = ?
      `, [costPerClick, link.merchant_id]);
    }
    
    // Redirect to the destination URL
    if (sharedLink.type === 'product') {
      return res.redirect(`/products/${sharedLink.link_id}?ref=${sharedLink.share_code}`);
    } else {
      return res.redirect(sharedLink.url);
    }
  } catch (err) {
    console.error('Shared link error:', err);
    return res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Cart route
app.get('/cart', async (req, res) => {
  try {
    // If user is not logged in, redirect to login
    if (!req.session.userId) {
      return res.redirect('/login?redirect=/cart');
    }

    const userId = req.session.userId;
    
    // Get cart items with product details
    const [cartItems] = await pool.query(`
      SELECT ci.*, p.name, p.price, p.image_url, p.merchant_id, 
             u.username as merchant_name, u.business_name
      FROM cart_items ci
      JOIN products p ON ci.product_id = p.id
      JOIN users u ON p.merchant_id = u.id
      WHERE ci.user_id = ?
    `, [userId]);
    
    // Calculate totals
    let subtotal = 0;
    let totalItems = 0;
    
    cartItems.forEach(item => {
      item.total = item.quantity * item.price;
      subtotal += item.total;
      totalItems += item.quantity;
    });
    
    // Get user data
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    
    res.render('user/cart', {
      user: users[0],
      cartItems: cartItems,
      subtotal: subtotal,
      totalItems: totalItems,
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Cart page error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// API to add product to cart
app.post('/api/cart/add', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { productId, quantity } = req.body;
    
    // Validate product exists
    const [products] = await pool.query('SELECT * FROM products WHERE id = ? AND is_active = true', [productId]);
    if (products.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Product not found or unavailable'
      });
    }
    
    // Check if product is already in cart
    const [existingItems] = await pool.query(
      'SELECT * FROM cart_items WHERE user_id = ? AND product_id = ?',
      [userId, productId]
    );
    
    if (existingItems.length > 0) {
      // Update quantity
      await pool.query(
        'UPDATE cart_items SET quantity = quantity + ? WHERE user_id = ? AND product_id = ?',
        [parseInt(quantity) || 1, userId, productId]
      );
    } else {
      // Add new item to cart
      await pool.query(
        'INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)',
        [userId, productId, parseInt(quantity) || 1]
      );
    }
    
    res.json({
      success: true,
      message: 'Product added to cart'
    });
  } catch (err) {
    console.error('Add to cart error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }

});
// User orders page
app.get('/user/orders', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    
    // Get user's orders with summary information
    const [orders] = await pool.query(`
      SELECT o.*, 
             COUNT(oi.id) as item_count
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      WHERE o.user_id = ?
      GROUP BY o.id
      ORDER BY o.created_at DESC
    `, [userId]);
    
    res.render('user/orders', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      orders: orders
    });
  } catch (err) {
    console.error('User orders error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Order details
// app.get('/user/orders/:id', isAuthenticated, async (req, res) => {
//   try {
//     const orderId = req.params.id;
//     const userId = req.session.userId;
    
//     // Get order details
//     const [orders] = await pool.query(`
//       SELECT * FROM orders
//       WHERE id = ? AND user_id = ?
//     `, [orderId, userId]);
    
//     if (orders.length === 0) {
//       return res.status(404).render('error', { message: 'Order not found.' });
//     }
    
//     // Get order items
//     const [orderItems] = await pool.query(`
//       SELECT oi.*, p.name, p.image_url
//       FROM order_items oi
//       JOIN products p ON oi.product_id = p.id
//       WHERE oi.order_id = ?
//     `, [orderId]);
    
//     res.render('user/order-details', {
//       user: {
//         id: req.session.userId,
//         username: req.session.username,
//         role: req.session.role
//       },
//       order: orders[0],
//       items: orderItems
//     });
//   } catch (err) {
//     console.error('Order details error:', err);
//     res.status(500).render('error', { message: 'Server error. Please try again later.' });
//   }
// });
// Order details
app.get('/user/orders/:id', isAuthenticated, async (req, res) => {
  try {
    const orderId = req.params.id;
    const userId = req.session.userId;
    
    // Get order details
    const [orders] = await pool.query(`
      SELECT * FROM orders
      WHERE id = ? AND user_id = ?
    `, [orderId, userId]);
    
    if (orders.length === 0) {
      return res.status(404).render('error', { message: 'Order not found.' });
    }
    
    // Get order items
    const [orderItems] = await pool.query(`
      SELECT oi.*, p.name, p.image_url, u.username as merchant_name
      FROM order_items oi
      JOIN products p ON oi.product_id = p.id
      JOIN users u ON p.merchant_id = u.id
      WHERE oi.order_id = ?
    `, [orderId]);
    
    // Get payment information from config
    const bankName = await getConfig('manual_payment_bank_name');
    const accountName = await getConfig('manual_payment_account_name');
    const accountNumber = await getConfig('manual_payment_account_number');
    const swiftCode = await getConfig('manual_payment_swift_code');
    
    const paymentInfo = {
      bankName: bankName || 'Bank of Africa',
      accountName: accountName || 'BenixSpace Ltd',
      accountNumber: accountNumber || '00012345678',
      swiftCode: swiftCode || null
    };
    
    res.render('user/order-details', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      order: orders[0],
      items: orderItems,
      paymentInfo: paymentInfo
    });
  } catch (err) {
    console.error('Order details error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});
// // API to update cart item quantity
// app.post('/api/cart/update', isAuthenticated, async (req, res) => {
//   try {
//     const userId = req.session.userId;
//     const { cartItemId, quantity } = req.body;
    
//     if (parseInt(quantity) <= 0) {
//       // Remove item if quantity is 0 or negative
//       await pool.query(
//         'DELETE FROM cart_items WHERE id = ? AND user_id = ?',
//         [cartItemId, userId]
//       );
//     } else {
//       // Update quantity
//       await pool.query(
//         'UPDATE cart_items SET quantity = ? WHERE id = ? AND user_id = ?',
//         [parseInt(quantity), cartItemId, userId]
//       );
//     }
    
//     res.json({
//       success: true,
//       message: 'Cart updated successfully'
//     });
//   } catch (err) {
//     console.error('Update cart error:', err);
//     res.status(500).json({
//       success: false,
//       message: 'Server error. Please try again later.'
//     });
//   }
// });

// // API to remove item from cart
// app.post('/api/cart/remove', isAuthenticated, async (req, res) => {
//   try {
//     const userId = req.session.userId;
//     const { cartItemId } = req.body;
    
//     await pool.query(
//       'DELETE FROM cart_items WHERE id = ? AND user_id = ?',
//       [cartItemId, userId]
//     );
    
//     res.json({
//       success: true,
//       message: 'Item removed from cart'
//     });
//   } catch (err) {
//     console.error('Remove from cart error:', err);
//     res.status(500).json({
//       success: false,
//       message: 'Server error. Please try again later.'
//     });
//   }
// });

// API to update cart item quantity
app.post('/api/cart/update', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { productId, quantity } = req.body;
    
    // Find the cart item
    const [cartItems] = await pool.query(
      'SELECT id FROM cart_items WHERE user_id = ? AND product_id = ?',
      [userId, productId]
    );
    
    if (cartItems.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Cart item not found'
      });
    }
    
    if (parseInt(quantity) <= 0) {
      // Remove item if quantity is 0 or negative
      await pool.query(
        'DELETE FROM cart_items WHERE user_id = ? AND product_id = ?',
        [userId, productId]
      );
    } else {
      // Update quantity
      await pool.query(
        'UPDATE cart_items SET quantity = ? WHERE user_id = ? AND product_id = ?',
        [parseInt(quantity), userId, productId]
      );
    }
    
    res.json({
      success: true,
      message: 'Cart updated successfully'
    });
  } catch (err) {
    console.error('Update cart error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});


// API route to create an order
app.post('/api/orders/create', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { shippingAddress, phoneNumber } = req.body;
    
    // Validate input
    if (!shippingAddress || !phoneNumber) {
      return res.status(400).json({
        success: false,
        message: 'Shipping address and phone number are required'
      });
    }
    
    // Get cart items
    const [cartItems] = await pool.query(`
      SELECT ci.*, p.name, p.price, p.merchant_id, p.commission_rate
      FROM cart_items ci
      JOIN products p ON ci.product_id = p.id
      WHERE ci.user_id = ?
    `, [userId]);
    
    if (cartItems.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Your cart is empty'
      });
    }
    
    // Calculate total amount
    let totalAmount = 0;
    cartItems.forEach(item => {
      totalAmount += item.price * item.quantity;
    });
    
    // Create new order
    const [orderResult] = await pool.query(`
      INSERT INTO orders (user_id, total_amount, status, shipping_address, phone_number)
      VALUES (?, ?, 'pending', ?, ?)
    `, [userId, totalAmount, shippingAddress, phoneNumber]);
    
    const orderId = orderResult.insertId;
    
    // Add all items to order_items
    for (const item of cartItems) {
      await pool.query(`
        INSERT INTO order_items (order_id, product_id, quantity, price, commission_earned)
        VALUES (?, ?, ?, ?, ?)
      `, [
        orderId, 
        item.product_id, 
        item.quantity, 
        item.price,
        0
      ]);
    }
    
    // Clear the cart
    await pool.query('DELETE FROM cart_items WHERE user_id = ?', [userId]);
    
    res.json({
      success: true,
      message: 'Order created successfully',
      orderId: orderId
    });
  } catch (err) {
    console.error('Order creation error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// API to remove item from cart
app.post('/api/cart/remove', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { productId } = req.body;
    
    // Remove item from cart
    await pool.query(
      'DELETE FROM cart_items WHERE user_id = ? AND product_id = ?',
      [userId, productId]
    );
    
    res.json({
      success: true,
      message: 'Item removed from cart'
    });
  } catch (err) {
    console.error('Remove from cart error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});
// // Profile routes
// app.get('/profile', isAuthenticated, async (req, res) => {
//   try {
//     const userId = req.session.userId;
//     const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
//     const user = users[0];

//     // Initialize default stats
//     const stats = {
//       totalLinks: 0,
//       totalClicks: 0,
//       totalEarnings: parseFloat(user.earnings || 0)
//     };

//     if (user.role === 'merchant') {
//       const [linkCount] = await pool.query('SELECT COUNT(*) as count FROM links WHERE merchant_id = ?', [userId]);
//       const [clickCount] = await pool.query(`
//         SELECT COUNT(*) as count FROM clicks c
//         JOIN shared_links sl ON c.shared_link_id = sl.id
//         JOIN links l ON sl.link_id = l.id
//         WHERE l.merchant_id = ?
//       `, [userId]);

//       stats.totalLinks = linkCount[0].count;
//       stats.totalClicks = clickCount[0].count;
//     } else {
//       const [linkCount] = await pool.query('SELECT COUNT(*) as count FROM shared_links WHERE user_id = ?', [userId]);
//       const [clickCount] = await pool.query(`
//         SELECT COUNT(*) as count FROM clicks c
//         JOIN shared_links sl ON c.shared_link_id = sl.id
//         WHERE sl.user_id = ?
//       `, [userId]);

//       stats.totalLinks = linkCount[0].count;
//       stats.totalClicks = clickCount[0].count;
//     }

//     return res.render('user/profile', { 
//       user, 
//       stats,
//       success: req.query.success,
//       error: req.query.error 
//     });
//   } catch (err) {
//     console.error('Profile page error:', err);
//     return res.status(500).render('error', { message: 'Server error. Please try again later.' });
//   }
// });

// Add merchant orders route
app.get('/merchant/orders', isAuthenticated, isMerchant, async (req, res) => {
  try {
    const merchantId = req.session.userId;
    
    // Get orders that include products from this merchant
    const [orders] = await pool.query(`
      SELECT DISTINCT o.*, u.username as customer_name,
             COUNT(oi.id) as item_count,
             SUM(CASE WHEN p.merchant_id = ? THEN oi.quantity ELSE 0 END) as merchant_items,
             SUM(CASE WHEN p.merchant_id = ? THEN (oi.price * oi.quantity) ELSE 0 END) as merchant_total
      FROM orders o
      JOIN order_items oi ON o.id = oi.order_id
      JOIN products p ON oi.product_id = p.id
      JOIN users u ON o.user_id = u.id
      WHERE p.merchant_id = ?
      GROUP BY o.id
      ORDER BY o.created_at DESC
    `, [merchantId, merchantId, merchantId]);
    
    res.render('merchant/orders', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      orders: orders,
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Merchant orders error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Add merchant order details route
app.get('/merchant/orders/:id', isAuthenticated, isMerchant, async (req, res) => {
  try {
    const orderId = req.params.id;
    const merchantId = req.session.userId;
    
    // Get order details
    const [orders] = await pool.query(`
      SELECT o.*, u.username as customer_name, u.email as customer_email
      FROM orders o
      JOIN users u ON o.user_id = u.id
      WHERE o.id = ?
    `, [orderId]);
    
    if (orders.length === 0) {
      return res.status(404).render('error', { message: 'Order not found.' });
    }
    
    // Get order items for this merchant only
    const [orderItems] = await pool.query(`
      SELECT oi.*, p.name, p.image_url, p.merchant_id
      FROM order_items oi
      JOIN products p ON oi.product_id = p.id
      WHERE oi.order_id = ? AND p.merchant_id = ?
    `, [orderId, merchantId]);
    
    // If no items found for this merchant, they shouldn't access this order
    if (orderItems.length === 0) {
      return res.status(403).render('error', { message: 'You do not have permission to view this order.' });
    }
    
    // Calculate merchant's total for this order
    let merchantTotal = 0;
    orderItems.forEach(item => {
      merchantTotal += item.price * item.quantity;
    });
    
    res.render('merchant/order-details', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      order: orders[0],
      items: orderItems,
      merchantTotal: merchantTotal,
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Merchant order details error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Add route to update order item status (for merchant's items only)
app.post('/merchant/orders/:id/update-status', isAuthenticated, isMerchant, async (req, res) => {
  try {
    const orderId = req.params.id;
    const merchantId = req.session.userId;
    const { status } = req.body;
    
    // Validate status
    const validStatuses = ['processing', 'shipped', 'delivered'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status'
      });
    }
    
    // Verify merchant has items in this order
    const [orderItems] = await pool.query(`
      SELECT oi.id
      FROM order_items oi
      JOIN products p ON oi.product_id = p.id
      WHERE oi.order_id = ? AND p.merchant_id = ?
    `, [orderId, merchantId]);
    
    if (orderItems.length === 0) {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to update this order'
      });
    }
    
    // Update order status
    await pool.query(`
      UPDATE orders
      SET status = ?
      WHERE id = ?
    `, [status, orderId]);
    
    return res.json({
      success: true,
      message: `Order status updated to ${status}`
    });
  } catch (err) {
    console.error('Update order status error:', err);
    return res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});
// Merchant product management routes
app.get('/merchant/products', isAuthenticated, isMerchant, async (req, res) => {
  try {
    const merchantId = req.session.userId;
    
    // Get all products for this merchant
    const [products] = await pool.query(`
      SELECT p.*, 
             COUNT(DISTINCT oi.id) as order_count,
             COALESCE(SUM(oi.quantity), 0) as total_sold
      FROM products p
      LEFT JOIN order_items oi ON p.id = oi.product_id
      WHERE p.merchant_id = ?
      GROUP BY p.id
      ORDER BY p.created_at DESC
    `, [merchantId]);
    
    console.log('Merchant products found:', products.length);
    
    res.render('merchant/products', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      products: products,
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Merchant products error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Form to create a new product
// Form to create a new product
app.get('/merchant/products/create', isAuthenticated, isMerchant, async (req, res) => {
  try {
    // Get default commission rate from config
    const commissionRate = await getConfig('commission_rate');
    
    res.render('merchant/product-form', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      product: null, // null means new product
      defaultCommissionRate: parseFloat(commissionRate), // Change variable name to match template
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Product form error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Create a new product
app.post('/merchant/products/create', isAuthenticated, isMerchant, upload.single('image'), async (req, res) => {
  try {
    const merchantId = req.session.userId;
    const {
      name,
      description,
      price,
      stock,
      category,
      commission_rate
    } = req.body;
    
    // Validate required fields
    if (!name || !price || !stock) {
      return res.redirect('/merchant/products/create?error=Name, price, and stock are required fields');
    }
    
    // Get the file path if an image was uploaded
    let imageUrl = null;
    if (req.file) {
      imageUrl = `/uploads/${req.file.filename}`;
    }
    
    // Insert the new product
    await pool.query(`
      INSERT INTO products (
        merchant_id,
        name, 
        description, 
        price, 
        stock,
        image_url, 
        category,
        commission_rate,
        is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, true)
    `, [
      merchantId,
      name,
      description || null,
      parseFloat(price),
      parseInt(stock),
      imageUrl,
      category || null,
      parseFloat(commission_rate) || 5.00  // Default to 5% if not specified
    ]);
    
    res.redirect('/merchant/products?success=Product created successfully');
  } catch (err) {
    console.error('Product creation error:', err);
    res.redirect('/merchant/products/create?error=Failed to create product. Please try again.');
  }
});

// Edit a product

app.get('/merchant/products/:id/edit', isAuthenticated, isMerchant, async (req, res) => {
  try {
    const productId = req.params.id;
    const merchantId = req.session.userId;
    
    // Get product details, ensuring it belongs to this merchant
    const [products] = await pool.query(`
      SELECT * FROM products
      WHERE id = ? AND merchant_id = ?
    `, [productId, merchantId]);
    
    if (products.length === 0) {
      return res.status(404).render('error', { message: 'Product not found or you don\'t have permission to edit it.' });
    }
    
    // Get default commission rate from config
    const commissionRate = await getConfig('commission_rate');
    
    res.render('merchant/product-form', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      product: products[0],
      defaultCommissionRate: parseFloat(commissionRate), // Change variable name here too
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Edit product form error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Update a product
app.post('/merchant/products/:id/edit', isAuthenticated, isMerchant, upload.single('image'), async (req, res) => {
  try {
    const productId = req.params.id;
    const merchantId = req.session.userId;
    const {
      name,
      description,
      price,
      stock,
      category,
      commission_rate,
      is_active
    } = req.body;
    
    // Verify product belongs to this merchant
    const [products] = await pool.query(`
      SELECT *
      FROM products
      WHERE id = ? AND merchant_id = ?
    `, [productId, merchantId]);
    
    if (products.length === 0) {
      return res.status(404).render('error', { message: 'Product not found or you don\'t have permission to edit it.' });
    }
    
    // Get the file path if a new image was uploaded
    let imageUrl = products[0].image_url;
    if (req.file) {
      imageUrl = `/uploads/${req.file.filename}`;
      
      // Delete old image if it exists
      if (products[0].image_url) {
        const oldImagePath = path.join(__dirname, 'public', products[0].image_url);
        if (fs.existsSync(oldImagePath)) {
          fs.unlinkSync(oldImagePath);
        }
      }
    }
    
    // Update the product
    await pool.query(`
      UPDATE products
      SET name = ?,
          description = ?,
          price = ?,
          stock = ?,
          image_url = ?,
          category = ?,
          commission_rate = ?,
          is_active = ?
      WHERE id = ? AND merchant_id = ?
    `, [
      name,
      description || null,
      parseFloat(price),
      parseInt(stock),
      imageUrl,
      category || null,
      parseFloat(commission_rate) || 5.00,
      is_active ? 1 : 0,
      productId,
      merchantId
    ]);
    
    res.redirect(`/merchant/products?success=Product updated successfully`);
  } catch (err) {
    console.error('Product update error:', err);
    res.redirect(`/merchant/products/${req.params.id}/edit?error=Failed to update product. Please try again.`);
  }
});

// View product details
app.get('/merchant/products/:id', isAuthenticated, isMerchant, async (req, res) => {
  try {
    const productId = req.params.id;
    const merchantId = req.session.userId;
    
    // Get product details, ensuring it belongs to this merchant
    const [products] = await pool.query(`
      SELECT *
      FROM products
      WHERE id = ? AND merchant_id = ?
    `, [productId, merchantId]);
    
    if (products.length === 0) {
      return res.status(404).render('error', { message: 'Product not found or you don\'t have permission to view it.' });
    }
    
    const product = products[0];
    
    // Get analytics data for this product
    const [analytics] = await pool.query(`
      SELECT 
        COUNT(DISTINCT oi.id) as total_orders,
        SUM(oi.quantity) as total_sold,
        SUM(oi.price * oi.quantity) as total_revenue
      FROM order_items oi
      WHERE oi.product_id = ?
    `, [productId]);
    
    // If no analytics records were found, initialize with zeros
    const analyticsData = analytics.length > 0 ? analytics[0] : { 
      total_orders: 0, 
      total_sold: 0, 
      total_revenue: 0 
    };
    
    // Get recent orders for this product
    const [orders] = await pool.query(`
      SELECT 
        o.id as order_id,
        o.created_at,
        o.status,
        oi.quantity,
        oi.price,
        u.username as customer_name
      FROM order_items oi
      JOIN orders o ON oi.order_id = o.id
      JOIN users u ON o.user_id = u.id
      WHERE oi.product_id = ?
      ORDER BY o.created_at DESC
      LIMIT 10
    `, [productId]);
    
    res.render('merchant/product-details', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      product: product,
      analytics: analyticsData,
      orders: orders,
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Merchant product details error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Delete a product
app.delete('/merchant/products/:id/delete', isAuthenticated, isMerchant, async (req, res) => {
  try {
    const productId = req.params.id;
    const merchantId = req.session.userId;
    
    // Verify product belongs to this merchant
    const [products] = await pool.query(`
      SELECT *
      FROM products
      WHERE id = ? AND merchant_id = ?
    `, [productId, merchantId]);
    
    if (products.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Product not found or you don\'t have permission to delete it'
      });
    }
    
    // Check if the product has any orders
    const [orderItems] = await pool.query(`
      SELECT COUNT(*) as count
      FROM order_items
      WHERE product_id = ?
    `, [productId]);
    
    if (orderItems[0].count > 0) {
      // If product has orders, just mark it as inactive instead of deleting
      await pool.query(`
        UPDATE products
        SET is_active = false
        WHERE id = ? AND merchant_id = ?
      `, [productId, merchantId]);
      
      return res.json({
        success: true,
        message: 'Product has been deactivated because it has associated orders'
      });
    }
    
    // Delete the product if it has no orders
    await pool.query(`
      DELETE FROM products
      WHERE id = ? AND merchant_id = ?
    `, [productId, merchantId]);
    
    // Delete product image if it exists
    if (products[0].image_url) {
      const imagePath = path.join(__dirname, 'public', products[0].image_url);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }
    
    res.json({
      success: true,
      message: 'Product deleted successfully'
    });
  } catch (err) {
    console.error('Delete product error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// Profile page route
app.get('/profile', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    
    // Get user data
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      return res.status(404).render('error', { message: 'User not found' });
    }
    
    const user = users[0];
    
    // Initialize stats object
    const stats = {
      totalLinks: 0,
      totalClicks: 0,
      totalEarnings: 0
    };
    
    // Get stats based on user role
    if (user.role === 'merchant') {
      // Get links count
      const [linkCountResults] = await pool.query('SELECT COUNT(*) as count FROM links WHERE merchant_id = ?', [userId]);
      stats.totalLinks = linkCountResults[0].count || 0;
      
      // Get total clicks from shared_links table
      const [clickResults] = await pool.query(`
        SELECT COALESCE(SUM(sl.clicks), 0) as totalClicks
        FROM links l
        LEFT JOIN shared_links sl ON l.id = sl.link_id
        WHERE l.merchant_id = ?
      `, [userId]);
      
      stats.totalClicks = clickResults[0].totalClicks || 0;
    } else if (user.role === 'user') {
      // Get user shared links count
      const [linkCountResults] = await pool.query('SELECT COUNT(*) as count FROM shared_links WHERE user_id = ?', [userId]);
      stats.totalLinks = linkCountResults[0].count || 0;
      
      // Get total clicks on user's shared links
      const [clickResults] = await pool.query('SELECT COALESCE(SUM(clicks), 0) as totalClicks FROM shared_links WHERE user_id = ?', [userId]);
      stats.totalClicks = clickResults[0].totalClicks || 0;
      
      // Get total earnings
      stats.totalEarnings = parseFloat(user.earnings || 0);
    }
    
    res.render('user/profile', { 
      user,
      stats,
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Profile page error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Route for sharing links
app.get('/links/:id/share', isAuthenticated, async (req, res) => {
  try {
    const linkId = req.params.id;
    const userId = req.session.userId;
    
    // Check if link exists
    const [links] = await pool.query('SELECT * FROM links WHERE id = ?', [linkId]);
    
    if (links.length === 0) {
      return res.status(404).render('error', { message: 'Link not found.' });
    }
    
    const link = links[0];
    
    // Check if user has already shared this link
    const [existingShares] = await pool.query(
      'SELECT * FROM shared_links WHERE link_id = ? AND user_id = ?',
      [linkId, userId]
    );
    
    let shareCode;
    
    if (existingShares.length > 0) {
      // User already has a share code for this link
      shareCode = existingShares[0].share_code;
    } else {
      // Generate a new share code
      shareCode = uuidv4().substring(0, 8);
      
      // Create a new shared link record
      await pool.query(
        'INSERT INTO shared_links (link_id, user_id, share_code) VALUES (?, ?, ?)',
        [linkId, userId, shareCode]
      );
    }
    
    res.render('user/share', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      link: link,
      shareCode: shareCode,
      shareUrl: `${req.protocol}://${req.get('host')}/l/${shareCode}`
    });
  } catch (err) {
    console.error('Link sharing error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

app.post('/profile/update', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const {
      username,
      email,
      current_password,
      new_password,
      business_name,
      business_description,
      account_name,
      account_number,
      bank_code
    } = req.body;

    // Check if username or email already exists
    const [existingUsers] = await pool.query(
      'SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?',
      [username, email, userId]
    );

    if (existingUsers.length > 0) {
      const [user] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
      return res.render('user/profile', {
        user: user[0],
        error: 'Username or email already in use'
      });
    }

    // Update basic info
    await pool.query(`
      UPDATE users 
      SET username = ?, 
          email = ?,
          business_name = ?,
          business_description = ?,
          account_name = ?,
          account_number = ?,
          bank_code = ?
      WHERE id = ?
    `, [
      username,
      email,
      business_name || null,
      business_description || null,
      account_name,
      account_number,
      bank_code,
      userId
    ]);

    // Update password if provided
    if (current_password && new_password) {
      const [user] = await pool.query('SELECT password FROM users WHERE id = ?', [userId]);
      const passwordMatch = await bcrypt.compare(current_password, user[0].password);

      if (!passwordMatch) {
        return res.render('user/profile', {
          user: { ...req.body, id: userId },
          error: 'Current password is incorrect'
        });
      }

      const hashedPassword = await bcrypt.hash(new_password, 10);
      await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId]);
    }

    // Get updated user data
    const [updatedUser] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    
    res.render('user/profile', {
      user: updatedUser[0],
      success: 'Profile updated successfully'
    });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

app.post('/register', async (req, res) => {
  try {
    const { username, email, password, confirmPassword, role, business_name, business_description } = req.body;
    
    // Basic validation
    if (password !== confirmPassword) {
      return res.render('auth', { page: 'register', error: 'Passwords do not match' });
    }
    
    // Validate role
    if (!['user', 'merchant'].includes(role)) {
      return res.render('auth', { page: 'register', error: 'Invalid role selected' });
    }
    
    // Additional validation for merchants
    if (role === 'merchant' && (!business_name || !business_description)) {
      return res.render('auth', { 
        page: 'register', 
        error: 'Business name and description are required for merchant accounts' 
      });
    }
    
    // Check if user exists
    const [existingUsers] = await pool.query(
      'SELECT * FROM users WHERE username = ? OR email = ?', 
      [username, email]
    );
    
    if (existingUsers.length > 0) {
      return res.render('auth', { 
        page: 'register', 
        error: 'Username or email already in use' 
      });
    }
    
    // Create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (username, email, password, role, business_name, business_description) VALUES (?, ?, ?, ?, ?, ?)',
      [username, email, hashedPassword, role, business_name || null, business_description || null]
    );
    
    // Set session
    req.session.userId = result.insertId;
    req.session.username = username;
    req.session.role = role;
    
    res.redirect('/dashboard');
  } catch (err) {
    console.error('Registration error:', err);
    res.render('auth', { page: 'register', error: 'Server error. Please try again.' });
  }
});

app.get('/register', (req, res) => {
  try{

    return res.render('auth', { page: 'register', error: null });
  

} catch (err) {
  console.error('Failed to load register page:', err);
  return res.status(500).render('error', { message: 'Server error. Please try again later.' });
}
});



// app.post('/register', async (req, res) => {
//   try {
//     const { username, email, password, confirmPassword } = req.body;
    
//     // Basic validation
//     if (password !== confirmPassword) {
//       return res.render('auth', { page: 'register', error: 'Passwords do not match' });
//     }
    
//     // Check if user exists
//     const [existingUsers] = await pool.query(
//       'SELECT * FROM users WHERE username = ? OR email = ?', 
//       [username, email]
//     );
    
//     if (existingUsers.length > 0) {
//       return res.render('auth', { 
//         page: 'register', 
//         error: 'Username or email already in use' 
//       });
//     }
    
//     // Create user
//     const hashedPassword = await bcrypt.hash(password, 10);
//     const [result] = await pool.query(
//       'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
//       [username, email, hashedPassword]
//     );
    
//     // Set session
//     req.session.userId = result.insertId;
//     req.session.username = username;
//     req.session.role = 'user';
    
//     res.redirect('/dashboard');
//   } catch (err) {
//     console.error('Registration error:', err);
//     res.render('auth', { page: 'register', error: 'Server error. Please try again.' });
//   }
// });

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Dashboard routes
app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    const user = users[0];
    
    let data = {
      user: user,
      stats: {}
    };
    
    if (user.role === 'admin') {
      // Admin dashboard data
      const [userCount] = await pool.query('SELECT COUNT(*) as count FROM users');
      const [merchantCount] = await pool.query('SELECT COUNT(*) as count FROM users WHERE role = ?', ['merchant']);
      const [linkCount] = await pool.query('SELECT COUNT(*) as count FROM links');
      const [clickCount] = await pool.query('SELECT COUNT(*) as count FROM clicks');

      // In the dashboard route, replace the existing gatewayStats query with this:
const [gatewayStats] = await pool.query(`
  SELECT 
    COALESCE(SUM(CASE 
      WHEN details LIKE '%via Umva Pay%' AND status = 'completed' 
      THEN amount 
    END), 0) as umvapayVolume,
    
    COUNT(CASE 
      WHEN details LIKE '%via Umva Pay%' AND status = 'completed' 
      THEN 1 
    END) as umvapayCount,
    
    COALESCE(SUM(CASE 
      WHEN details LIKE '%via Umva Pay%' AND type = 'upgrade' AND status = 'completed' 
      THEN amount 
    END), 0) as umvapayUpgrades,
    
    COALESCE(SUM(CASE 
      WHEN details LIKE '%via Umva Pay%' AND type = 'withdrawal' AND status = 'completed' 
      THEN amount 
    END), 0) as umvapayWithdrawals
  FROM transactions
  WHERE details LIKE '%via Umva Pay%'
`);

      // Get recent gateway transactions
      const [recentGatewayTransactions] = await pool.query(`
        SELECT t.*, u.username 
        FROM transactions t 
        JOIN users u ON t.user_id = u.id 
        WHERE t.details LIKE '%via Umva Pay%'
        ORDER BY t.created_at DESC 
        LIMIT 10
      `);
      
      data.stats = {
        userCount: userCount[0].count,
        merchantCount: merchantCount[0].count,
        linkCount: linkCount[0].count,
        clickCount: clickCount[0].count,
        recentTransactions: recentGatewayTransactions,
        ...gatewayStats[0],
        recentGatewayTransactions
      };
      
      // Get config settings
      const [configSettings] = await pool.query('SELECT * FROM config');
      data.config = configSettings;
    } 
    else if (user.role === 'merchant') {
      // Merchant dashboard data
      const [links] = await pool.query('SELECT * FROM links WHERE merchant_id = ?', [userId]);
      const [totalClicks] = await pool.query(`
        SELECT COUNT(*) as count FROM clicks c
        JOIN shared_links sl ON c.shared_link_id = sl.id
        JOIN links l ON sl.link_id = l.id
        WHERE l.merchant_id = ?
      `, [userId]);
      
      data.stats = {
        linkCount: links.length,
        totalClicks: totalClicks[0].count,
        amountToPay: parseFloat(user.amount_to_pay || 0).toFixed(2),
        paidBalance: parseFloat(user.paid_balance || 0).toFixed(2),
        links: links
      };
    } 
    else {
      // Regular user dashboard data
      const [sharedLinks] = await pool.query(`
        SELECT sl.*, l.title, l.type, l.url, l.image_url 
        FROM shared_links sl
        JOIN links l ON sl.link_id = l.id
        WHERE sl.user_id = ?
      `, [userId]);
      
      const [totalClicks] = await pool.query(`
        SELECT COUNT(*) as count FROM clicks c
        JOIN shared_links sl ON c.shared_link_id = sl.id
        WHERE sl.user_id = ?
      `, [userId]);
      
      data.stats = {
        sharedLinkCount: sharedLinks.length,
        totalClicks: totalClicks[0].count,
        totalEarnings: user.earnings,
        sharedLinks: sharedLinks
      };
      
      // Fetch available links to share
      const [availableLinks] = await pool.query(`
        SELECT l.*, u.username as merchant_name, u.business_name
        FROM links l
        JOIN users u ON l.merchant_id = u.id
        WHERE l.is_active = true
        ORDER BY l.created_at DESC
        LIMIT 20
      `);
      
      data.availableLinks = availableLinks;
    }
    
    res.render('dashboard', data);
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Wallet route
app.get('/wallet', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    const user = users[0];

    // Get minimum payout amount from config
    const minPayout = await getConfig('min_payout');
    
    // Get manual payment instructions
    const manualInstructions = await getConfig('manual_payment_instructions');

    // Get user's transactions
    const [transactions] = await pool.query(`
      SELECT * FROM transactions 
      WHERE user_id = ? AND (type = 'commission' OR type = 'withdrawal')
      ORDER BY created_at DESC
    `, [userId]);

    res.render('user/wallet', { 
      user,
      transactions,
      minPayout: parseFloat(minPayout),
      manualInstructions: manualInstructions || 'Please transfer the amount to our account and upload a screenshot/receipt as proof of payment.'
    });
  } catch (err) {
    console.error('Wallet page error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Profile routes
app.get('/profile', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    const user = users[0];

    // Initialize default stats
    const stats = {
      totalLinks: 0,
      totalClicks: 0,
      totalEarnings: parseFloat(user.earnings || 0)
    };

    if (user.role === 'merchant') {
      const [linkCount] = await pool.query('SELECT COUNT(*) as count FROM links WHERE merchant_id = ?', [userId]);
      const [clickCount] = await pool.query(`
        SELECT COUNT(*) as count FROM clicks c
        JOIN shared_links sl ON c.shared_link_id = sl.id
        JOIN links l ON sl.link_id = l.id
        WHERE l.merchant_id = ?
      `, [userId]);

      stats.totalLinks = linkCount[0].count;
      stats.totalClicks = clickCount[0].count;
    } else {
      const [linkCount] = await pool.query('SELECT COUNT(*) as count FROM shared_links WHERE user_id = ?', [userId]);
      const [clickCount] = await pool.query(`
        SELECT COUNT(*) as count FROM clicks c
        JOIN shared_links sl ON c.shared_link_id = sl.id
        WHERE sl.user_id = ?
      `, [userId]);

      stats.totalLinks = linkCount[0].count;
      stats.totalClicks = clickCount[0].count;
    }

    return res.render('user/profile', { 
      user, 
      stats,
      success: req.query.success,
      error: req.query.error 
    });
  } catch (err) {
    console.error('Profile page error:', err);
    return res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Route for sharing links
app.get('/links/:id/share', isAuthenticated, async (req, res) => {
  try {
    const linkId = req.params.id;
    const userId = req.session.userId;
    
    // Check if link exists
    const [links] = await pool.query('SELECT * FROM links WHERE id = ?', [linkId]);
    
    if (links.length === 0) {
      return res.status(404).render('error', { message: 'Link not found.' });
    }
    
    const link = links[0];
    
    // Check if user has already shared this link
    const [existingShares] = await pool.query(
      'SELECT * FROM shared_links WHERE link_id = ? AND user_id = ?',
      [linkId, userId]
    );
    
    let shareCode;
    
    if (existingShares.length > 0) {
      // User already has a share code for this link
      shareCode = existingShares[0].share_code;
    } else {
      // Generate a new share code
      shareCode = uuidv4().substring(0, 8);
      
      // Create a new shared link record
      await pool.query(
        'INSERT INTO shared_links (link_id, user_id, share_code) VALUES (?, ?, ?)',
        [linkId, userId, shareCode]
      );
    }
    
    res.render('user/share', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      link: link,
      shareCode: shareCode,
      shareUrl: `${req.protocol}://${req.get('host')}/l/${shareCode}`
    });
  } catch (err) {
    console.error('Link sharing error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

app.post('/profile/update', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const {
      username,
      email,
      current_password,
      new_password,
      business_name,
      business_description,
      account_name,
      account_number,
      bank_code
    } = req.body;

    // Check if username or email already exists
    const [existingUsers] = await pool.query(
      'SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?',
      [username, email, userId]
    );

    if (existingUsers.length > 0) {
      const [user] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
      return res.render('user/profile', {
        user: user[0],
        error: 'Username or email already in use'
      });
    }

    // Update basic info
    await pool.query(`
      UPDATE users 
      SET username = ?, 
          email = ?,
          business_name = ?,
          business_description = ?,
          account_name = ?,
          account_number = ?,
          bank_code = ?
      WHERE id = ?
    `, [
      username,
      email,
      business_name || null,
      business_description || null,
      account_name,
      account_number,
      bank_code,
      userId
    ]);

    // Update password if provided
    if (current_password && new_password) {
      const [user] = await pool.query('SELECT password FROM users WHERE id = ?', [userId]);
      const passwordMatch = await bcrypt.compare(current_password, user[0].password);

      if (!passwordMatch) {
        return res.render('user/profile', {
          user: { ...req.body, id: userId },
          error: 'Current password is incorrect'
        });
      }

      const hashedPassword = await bcrypt.hash(new_password, 10);
      await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId]);
    }

    // Get updated user data
    const [updatedUser] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    
    res.render('user/profile', {
      user: updatedUser[0],
      success: 'Profile updated successfully'
    });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

app.post('/register', async (req, res) => {
  try {
    const { username, email, password, confirmPassword, role, business_name, business_description } = req.body;
    
    // Basic validation
    if (password !== confirmPassword) {
      return res.render('auth', { page: 'register', error: 'Passwords do not match' });
    }
    
    // Validate role
    if (!['user', 'merchant'].includes(role)) {
      return res.render('auth', { page: 'register', error: 'Invalid role selected' });
    }
    
    // Additional validation for merchants
    if (role === 'merchant' && (!business_name || !business_description)) {
      return res.render('auth', { 
        page: 'register', 
        error: 'Business name and description are required for merchant accounts' 
      });
    }
    
    // Check if user exists
    const [existingUsers] = await pool.query(
      'SELECT * FROM users WHERE username = ? OR email = ?', 
      [username, email]
    );
    
    if (existingUsers.length > 0) {
      return res.render('auth', { 
        page: 'register', 
        error: 'Username or email already in use' 
      });
    }
    
    // Create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (username, email, password, role, business_name, business_description) VALUES (?, ?, ?, ?, ?, ?)',
      [username, email, hashedPassword, role, business_name || null, business_description || null]
    );
    
    // Set session
    req.session.userId = result.insertId;
    req.session.username = username;
    req.session.role = role;
    
    res.redirect('/dashboard');
  } catch (err) {
    console.error('Registration error:', err);
    res.render('auth', { page: 'register', error: 'Server error. Please try again.' });
  }
});

app.get('/register', (req, res) => {
  try{

    return res.render('auth', { page: 'register', error: null });
  

} catch (err) {
  console.error('Failed to load register page:', err);
  return res.status(500).render('error', { message: 'Server error. Please try again later.' });
}
});



// app.post('/register', async (req, res) => {
//   try {
//     const { username, email, password, confirmPassword } = req.body;
    
//     // Basic validation
//     if (password !== confirmPassword) {
//       return res.render('auth', { page: 'register', error: 'Passwords do not match' });
//     }
    
//     // Check if user exists
//     const [existingUsers] = await pool.query(
//       'SELECT * FROM users WHERE username = ? OR email = ?', 
//       [username, email]
//     );
    
//     if (existingUsers.length > 0) {
//       return res.render('auth', { 
//         page: 'register', 
//         error: 'Username or email already in use' 
//       });
//     }
    
//     // Create user
//     const hashedPassword = await bcrypt.hash(password, 10);
//     const [result] = await pool.query(
//       'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
//       [username, email, hashedPassword]
//     );
    
//     // Set session
//     req.session.userId = result.insertId;
//     req.session.username = username;
//     req.session.role = 'user';
    
//     res.redirect('/dashboard');
//   } catch (err) {
//     console.error('Registration error:', err);
//     res.render('auth', { page: 'register', error: 'Server error. Please try again.' });
//   }
// });

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Dashboard routes
app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    const user = users[0];
    
    let data = {
      user: user,
      stats: {}
    };
    
    if (user.role === 'admin') {
      // Admin dashboard data
      const [userCount] = await pool.query('SELECT COUNT(*) as count FROM users');
      const [merchantCount] = await pool.query('SELECT COUNT(*) as count FROM users WHERE role = ?', ['merchant']);
      const [linkCount] = await pool.query('SELECT COUNT(*) as count FROM links');
      const [clickCount] = await pool.query('SELECT COUNT(*) as count FROM clicks');

      // In the dashboard route, replace the existing gatewayStats query with this:
const [gatewayStats] = await pool.query(`
  SELECT 
    COALESCE(SUM(CASE 
      WHEN details LIKE '%via Umva Pay%' AND status = 'completed' 
      THEN amount 
    END), 0) as umvapayVolume,
    
    COUNT(CASE 
      WHEN details LIKE '%via Umva Pay%' AND status = 'completed' 
      THEN 1 
    END) as umvapayCount,
    
    COALESCE(SUM(CASE 
      WHEN details LIKE '%via Umva Pay%' AND type = 'upgrade' AND status = 'completed' 
      THEN amount 
    END), 0) as umvapayUpgrades,
    
    COALESCE(SUM(CASE 
      WHEN details LIKE '%via Umva Pay%' AND type = 'withdrawal' AND status = 'completed' 
      THEN amount 
    END), 0) as umvapayWithdrawals
  FROM transactions
  WHERE details LIKE '%via Umva Pay%'
`);

      // Get recent gateway transactions
      const [recentGatewayTransactions] = await pool.query(`
        SELECT t.*, u.username 
        FROM transactions t 
        JOIN users u ON t.user_id = u.id 
        WHERE t.details LIKE '%via Umva Pay%'
        ORDER BY t.created_at DESC 
        LIMIT 10
      `);
      
      data.stats = {
        userCount: userCount[0].count,
        merchantCount: merchantCount[0].count,
        linkCount: linkCount[0].count,
        clickCount: clickCount[0].count,
        recentTransactions: recentGatewayTransactions,
        ...gatewayStats[0],
        recentGatewayTransactions
      };
      
      // Get config settings
      const [configSettings] = await pool.query('SELECT * FROM config');
      data.config = configSettings;
    } 
    else if (user.role === 'merchant') {
      // Merchant dashboard data
      const [links] = await pool.query('SELECT * FROM links WHERE merchant_id = ?', [userId]);
      const [totalClicks] = await pool.query(`
        SELECT COUNT(*) as count FROM clicks c
        JOIN shared_links sl ON c.shared_link_id = sl.id
        JOIN links l ON sl.link_id = l.id
        WHERE l.merchant_id = ?
      `, [userId]);
      
      data.stats = {
        linkCount: links.length,
        totalClicks: totalClicks[0].count,
        amountToPay: parseFloat(user.amount_to_pay || 0).toFixed(2),
        paidBalance: parseFloat(user.paid_balance || 0).toFixed(2),
        links: links
      };
    } 
    else {
      // Regular user dashboard data
      const [sharedLinks] = await pool.query(`
        SELECT sl.*, l.title, l.type, l.url, l.image_url 
        FROM shared_links sl
        JOIN links l ON sl.link_id = l.id
        WHERE sl.user_id = ?
      `, [userId]);
      
      const [totalClicks] = await pool.query(`
        SELECT COUNT(*) as count FROM clicks c
        JOIN shared_links sl ON c.shared_link_id = sl.id
        WHERE sl.user_id = ?
      `, [userId]);
      
      data.stats = {
        sharedLinkCount: sharedLinks.length,
        totalClicks: totalClicks[0].count,
        totalEarnings: user.earnings,
        sharedLinks: sharedLinks
      };
      
      // Fetch available links to share
      const [availableLinks] = await pool.query(`
        SELECT l.*, u.username as merchant_name, u.business_name
        FROM links l
        JOIN users u ON l.merchant_id = u.id
        WHERE l.is_active = true
        ORDER BY l.created_at DESC
        LIMIT 20
      `);
      
      data.availableLinks = availableLinks;
    }
    
    res.render('dashboard', data);
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Wallet route
app.get('/wallet', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    const user = users[0];

    // Get minimum payout amount from config
    const minPayout = await getConfig('min_payout');
    
    // Get manual payment instructions
    const manualInstructions = await getConfig('manual_payment_instructions');

    // Get user's transactions
    const [transactions] = await pool.query(`
      SELECT * FROM transactions 
      WHERE user_id = ? AND (type = 'commission' OR type = 'withdrawal')
      ORDER BY created_at DESC
    `, [userId]);

    res.render('user/wallet', { 
      user,
      transactions,
      minPayout: parseFloat(minPayout),
      manualInstructions: manualInstructions || 'Please transfer the amount to our account and upload a screenshot/receipt as proof of payment.'
    });
  } catch (err) {
    console.error('Wallet page error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Profile routes
app.get('/profile', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    const user = users[0];

    // Initialize default stats
    const stats = {
      totalLinks: 0,
      totalClicks: 0,
      totalEarnings: parseFloat(user.earnings || 0)
    };

    if (user.role === 'merchant') {
      const [linkCount] = await pool.query('SELECT COUNT(*) as count FROM links WHERE merchant_id = ?', [userId]);
      const [clickCount] = await pool.query(`
        SELECT COUNT(*) as count FROM clicks c
        JOIN shared_links sl ON c.shared_link_id = sl.id
        JOIN links l ON sl.link_id = l.id
        WHERE l.merchant_id = ?
      `, [userId]);

      stats.totalLinks = linkCount[0].count;
      stats.totalClicks = clickCount[0].count;
    } else {
      const [linkCount] = await pool.query('SELECT COUNT(*) as count FROM shared_links WHERE user_id = ?', [userId]);
      const [clickCount] = await pool.query(`
        SELECT COUNT(*) as count FROM clicks c
        JOIN shared_links sl ON c.shared_link_id = sl.id
        WHERE sl.user_id = ?
      `, [userId]);

      stats.totalLinks = linkCount[0].count;
      stats.totalClicks = clickCount[0].count;
    }

    return res.render('user/profile', { 
      user, 
      stats,
      success: req.query.success,
      error: req.query.error 
    });
  } catch (err) {
    console.error('Profile page error:', err);
    return res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Merchant link management routes
app.get('/merchant/links', isAuthenticated, isMerchant, async (req, res) => {
  try {
    const userId = req.session.userId;
    
    // Get all links for this merchant
    const [links] = await pool.query(`
      SELECT l.*, 
             COUNT(DISTINCT sl.id) as share_count,
             SUM(sl.clicks) as total_clicks
      FROM links l
      LEFT JOIN shared_links sl ON l.id = sl.link_id
      WHERE l.merchant_id = ?
      GROUP BY l.id
      ORDER BY l.created_at DESC
    `, [userId]);
    
    res.render('merchant/links', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      links: links,
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Merchant links error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

app.get('/merchant/links/create', isAuthenticated, isMerchant, async (req, res) => {
  try {
    // Get cost per click from config
    const costPerClick = await getConfig('cost_per_click');
    
    res.render('merchant/link-form', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      link: null, // null means new link
      costPerClick: parseFloat(costPerClick),
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Link form error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

app.post('/merchant/links/create', isAuthenticated, isMerchant, upload.single('image'), async (req, res) => {
  try {
    const userId = req.session.userId;
    const {
      title,
      description,
      type,
      url,
      category,
      click_target,
      cost_per_click
    } = req.body;
    
    // Validate merchant has enough balance
    const [merchants] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    const merchant = merchants[0];
    
    // Get the file path if an image was uploaded
    let imageUrl = null;
    if (req.file) {
      imageUrl = `/uploads/${req.file.filename}`;
    }
    
    // Calculate total cost
    const totalCost = parseFloat(click_target) * parseFloat(cost_per_click);
    
    // Insert the new link
    await pool.query(`
      INSERT INTO links (
        title, 
        description, 
        merchant_id, 
        type, 
        url, 
        image_url, 
        category, 
        click_target, 
        cost_per_click
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      title,
      description,
      userId,
      type,
      url,
      imageUrl,
      category,
      click_target,
      cost_per_click
    ]);
    
    res.redirect('/merchant/links?success=Link created successfully');
  } catch (err) {
    console.error('Link creation error:', err);
    res.redirect('/merchant/links/create?error=Failed to create link. Please try again.');
  }
});

app.get('/merchant/links/:id/edit', isAuthenticated, isMerchant, async (req, res) => {
  try {
    const linkId = req.params.id;
    const userId = req.session.userId;
    
    // Get link details, ensuring it belongs to this merchant
    const [links] = await pool.query(`
      SELECT * FROM links
      WHERE id = ? AND merchant_id = ?
    `, [linkId, userId]);
    
    if (links.length === 0) {
      return res.status(404).render('error', { message: 'Link not found or you don\'t have permission to edit it.' });
    }
    
    // Get cost per click from config
    const costPerClick = await getConfig('cost_per_click');
    
    res.render('merchant/link-form', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      link: links[0],
      costPerClick: parseFloat(costPerClick),
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Edit link form error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

app.post('/merchant/links/:id/edit', isAuthenticated, isMerchant, upload.single('image'), async (req, res) => {
  try {
    const linkId = req.params.id;
    const userId = req.session.userId;
    const {
      title,
      description,
      type,
      url,
      category,
      click_target,
      cost_per_click,
      is_active
    } = req.body;
    
    // Verify link belongs to this merchant
    const [links] = await pool.query(`
      SELECT l.*
      FROM links l
      WHERE l.id = ? AND l.merchant_id = ?
    `, [linkId, userId]);
    
    if (links.length === 0) {
      return res.status(404).render('error', { message: 'Link not found or you don\'t have permission to edit it.' });
    }
    
    // Get the file path if a new image was uploaded
    let imageUrl = links[0].image_url;
    if (req.file) {
      imageUrl = `/uploads/${req.file.filename}`;
      
      // Delete old image if it exists
      if (links[0].image_url) {
        const oldImagePath = path.join(__dirname, 'public', links[0].image_url);
        if (fs.existsSync(oldImagePath)) {
          fs.unlinkSync(oldImagePath);
        }
      }
    }
    
    // Update the link
    await pool.query(`
      UPDATE links
      SET title = ?,
          description = ?,
          type = ?,
          url = ?,
          image_url = ?,
          category = ?,
          click_target = ?,
          cost_per_click = ?,
          is_active = ?
      WHERE id = ? AND merchant_id = ?
    `, [
      title,
      description,
      type,
      url,
      imageUrl,
      category,
      click_target,
      cost_per_click,
      is_active ? 1 : 0,
      linkId,
      userId
    ]);
    
    res.redirect(`/merchant/links?success=Link updated successfully`);
  } catch (err) {
    console.error('Link update error:', err);
    res.redirect(`/merchant/links/${req.params.id}/edit?error=Failed to update link. Please try again.`);
  }
});

// Route to view a specific merchant link
app.get('/merchant/links/:id', isAuthenticated, isMerchant, async (req, res) => {
  try {
    const linkId = req.params.id;
    const userId = req.session.userId;
    
    // Get link details, ensuring it belongs to this merchant
    const [links] = await pool.query(`
      SELECT l.*
      FROM links l
      WHERE l.id = ? AND l.merchant_id = ?
    `, [linkId, userId]);
    
    if (links.length === 0) {
      return res.status(404).render('error', { message: 'Link not found or you don\'t have permission to view it.' });
    }
    
    const link = links[0];
    
    // Get analytics data for this link with corrected queries
    const [analytics] = await pool.query(`
      SELECT 
        COUNT(DISTINCT sl.id) as total_shares,
        SUM(sl.clicks) as total_clicks,
        COALESCE(SUM(sl.earnings), 0) as total_earnings
      FROM links l
      LEFT JOIN shared_links sl ON l.id = sl.link_id
      WHERE l.id = ?
      GROUP BY l.id
    `, [linkId]);
    
    // If no analytics records were found, initialize with zeros
    const analyticsData = analytics.length > 0 ? analytics[0] : { 
      total_shares: 0, 
      total_clicks: 0, 
      total_earnings: 0 
    };
    
    // Get users who shared this link with correct click count calculation
    const [shares] = await pool.query(`
      SELECT 
        sl.*, 
        u.username, 
        sl.clicks as click_count,
        COALESCE(sl.earnings, 0) as user_earnings
      FROM shared_links sl
      JOIN users u ON sl.user_id = u.id
      WHERE sl.link_id = ?
      ORDER BY sl.clicks DESC
    `, [linkId]);
    
    res.render('merchant/link-details', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      link: link,
      analytics: analyticsData,
      shares: shares,
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Merchant link details error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Admin merchants route
// app.get('/admin/merchants', isAuthenticated, isAdmin, async (req, res) => {
//   try {
//     // Get all merchants with their account details
//     const [merchants] = await pool.query(`
//       SELECT * FROM users 
//       WHERE role = 'merchant'
//       ORDER BY created_at DESC
//     `);
    
//     // Get merchant payments and balance stats
//     const merchantsWithStats = await Promise.all(merchants.map(async (merchant) => {
//       // Get total amount paid
//       const [payments] = await pool.query(`
//         SELECT SUM(amount) as total_paid
//         FROM transactions
//         WHERE user_id = ? AND type = 'payment' AND status = 'completed'
//       `, [merchant.id]);
      
//       // Get total links count
//       const [links] = await pool.query(`
//         SELECT COUNT(*) as total_links
//         FROM links
//         WHERE merchant_id = ?
//       `, [merchant.id]);
      
//       return {
//         ...merchant,
//         total_paid: payments[0].total_paid || 0,
//         total_links: links[0].total_links || 0
//       };
//     }));
    
//     res.render('admin/merchants', { 
//       merchants: merchantsWithStats,
//       success: req.query.success,
//       error: req.query.error
//     });
//   } catch (err) {
//     console.error('Merchants page error:', err);
//     res.status(500).render('error', { message: 'Server error. Please try again later.' });
//   }
// });
app.get('/admin/merchants', isAuthenticated, isAdmin, async (req, res) => {
  try {
    // Get all merchants with their account details
    const [merchants] = await pool.query(`
      SELECT * FROM users 
      WHERE role = 'merchant'
      ORDER BY created_at DESC
    `);
    
    // Get merchant payments and balance stats
    const merchantsWithStats = await Promise.all(merchants.map(async (merchant) => {
      // Get total amount paid
      const [payments] = await pool.query(`
        SELECT SUM(amount) as total_paid
        FROM transactions
        WHERE user_id = ? AND type = 'payment' AND status = 'completed'
      `, [merchant.id]);
      
      // Get total links count
      const [links] = await pool.query(`
        SELECT COUNT(*) as total_links
        FROM links
        WHERE merchant_id = ?
      `, [merchant.id]);
      
      return {
        ...merchant,
        total_paid: payments[0].total_paid || 0,
        total_links: links[0].total_links || 0
      };
    }));
    
    // Get recent merchant payments
    const [paymentRecords] = await pool.query(`
      SELECT t.*, u.username 
      FROM transactions t
      JOIN users u ON t.user_id = u.id
      WHERE t.type = 'payment' 
      ORDER BY t.created_at DESC
      LIMIT 20
    `);
    
    res.render('admin/merchants', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      merchants: merchantsWithStats,
      payments: paymentRecords,
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Merchants page error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});
// Route to edit a merchant
app.get('/admin/merchants/:id/edit', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const merchantId = req.params.id;
    
    // Get merchant details
    const [merchants] = await pool.query('SELECT * FROM users WHERE id = ? AND role = "merchant"', [merchantId]);
    
    if (merchants.length === 0) {
      return res.status(404).render('error', { message: 'Merchant not found' });
    }
    
    res.render('admin/merchant-edit', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      merchant: merchants[0],
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Edit merchant error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Route to update a merchant
app.post('/admin/merchants/:id/update', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const merchantId = req.params.id;
    const { username, email, business_name, business_description, is_verified } = req.body;
    
    // Update merchant details
    await pool.query(`
      UPDATE users 
      SET username = ?, email = ?, business_name = ?, business_description = ?, is_verified = ?
      WHERE id = ? AND role = "merchant"
    `, [
      username,
      email,
      business_name || null,
      business_description || null,
      is_verified === 'on' ? true : false,
      merchantId
    ]);
    
    res.redirect('/admin/merchants?success=Merchant updated successfully');
  } catch (err) {
    console.error('Update merchant error:', err);
    res.redirect(`/admin/merchants/${req.params.id}/edit?error=Error updating merchant`);
  }
});
// Route to mark a merchant as paid
app.post('/admin/merchants/:id/mark-paid', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const merchantId = req.params.id;
    
    // Get merchant details
    const [merchants] = await pool.query('SELECT * FROM users WHERE id = ? AND role = "merchant"', [merchantId]);
    
    if (merchants.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Merchant not found'
      });
    }
    
    const merchant = merchants[0];
    const amountToPay = parseFloat(merchant.amount_to_pay) || 0;
    
    if (amountToPay <= 0) {
      return res.json({
        success: true,
        message: 'Merchant has no outstanding balance'
      });
    }
    
    // Record payment transaction
    await pool.query(`
      INSERT INTO transactions (
        user_id, type, amount, status, details
      ) VALUES (?, ?, ?, ?, ?)
    `, [
      merchantId,
      'payment',
      amountToPay,
      'completed',
      'Payment processed by admin'
    ]);
    
    // Update merchant's payment status
    await pool.query(`
      UPDATE users 
      SET paid_balance = paid_balance + ?, amount_to_pay = 0
      WHERE id = ?
    `, [amountToPay, merchantId]);
    
    res.json({
      success: true,
      message: 'Merchant marked as paid successfully',
      amount: amountToPay
    });
  } catch (err) {
    console.error('Mark merchant as paid error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// Route to delete a merchant
app.delete('/admin/merchants/:id/delete', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const merchantId = req.params.id;
    
    // Check if merchant exists
    const [merchants] = await pool.query('SELECT * FROM users WHERE id = ? AND role = "merchant"', [merchantId]);
    
    if (merchants.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Merchant not found'
      });
    }
    
    // Don't allow admins to delete themselves
    if (merchantId == req.session.userId) {
      return res.status(400).json({
        success: false,
        message: 'You cannot delete your own account'
      });
    }
    
    // Delete merchant (in a real application, you might want to soft-delete instead)
    await pool.query('DELETE FROM users WHERE id = ?', [merchantId]);
    
    res.json({
      success: true,
      message: 'Merchant deleted successfully'
    });
  } catch (err) {
    console.error('Delete merchant error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});
// Route to create a new merchant from admin panel
app.post('/admin/merchants/create', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { username, email, password, business_name, business_description, is_verified } = req.body;
    
    // Check if username or email already exists
    const [existingUsers] = await pool.query(
      'SELECT * FROM users WHERE username = ? OR email = ?',
      [username, email]
    );
    
    if (existingUsers.length > 0) {
      return res.redirect('/admin/merchants?error=Username or email already in use');
    }
    
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create the merchant account
    await pool.query(`
      INSERT INTO users (
        username, email, password, role, business_name, 
        business_description, is_verified, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
    `, [
      username,
      email,
      hashedPassword,
      'merchant',
      business_name || null,
      business_description || null,
      is_verified === 'on' ? true : false
    ]);
    
    res.redirect('/admin/merchants?success=Merchant created successfully');
  } catch (err) {
    console.error('Create merchant error:', err);
    res.redirect('/admin/merchants?error=Error creating merchant');
  }
});
// Admin users management route
app.get('/admin/users', isAuthenticated, isAdmin, async (req, res) => {
  try {
    // Get ALL users (including merchants)
    const [users] = await pool.query(`
      SELECT * FROM users 
      ORDER BY created_at DESC
    `);
    
    // Get recent user registrations
    const [recentRegistrations] = await pool.query(`
      SELECT * FROM users
      WHERE role = 'user'
      ORDER BY created_at DESC
      LIMIT 10
    `);
    
    // Get user statistics
    const [userStats] = await pool.query(`
      SELECT 
        COUNT(*) as total_users,
        SUM(CASE WHEN role = 'user' THEN 1 ELSE 0 END) as regular_users,
        SUM(CASE WHEN role = 'merchant' THEN 1 ELSE 0 END) as merchant_users,
        SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admin_users,
        SUM(CASE WHEN has_lifetime_commission = 1 THEN 1 ELSE 0 END) as premium_users
      FROM users
    `);
    
    res.render('admin/users', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      users: users,
      recentRegistrations: recentRegistrations,
      stats: userStats[0],
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Admin users page error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Route to toggle user premium status
app.post('/admin/users/:id/toggle-premium', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    
    // Get current user status
    const [users] = await pool.query('SELECT has_lifetime_commission FROM users WHERE id = ?', [userId]);
    
    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    const currentStatus = users[0].has_lifetime_commission ? true : false;
    const newStatus = !currentStatus;
    
    // Update premium status
    await pool.query('UPDATE users SET has_lifetime_commission = ? WHERE id = ?', [newStatus, userId]);
    
    res.json({
      success: true,
      message: `User premium status updated to ${newStatus ? 'premium' : 'standard'}`,
      newStatus: newStatus
    });
  } catch (err) {
    console.error('Toggle premium status error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// Route to update a user's details
app.post('/admin/users/:id/update', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { username, email, role, wallet, has_lifetime_commission, notes } = req.body;
    
    // Validate inputs
    if (!username || !email || !role) {
      return res.status(400).json({
        success: false,
        message: 'Username, email and role are required'
      });
    }
    
    // Check if user exists
    const [existingUser] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    
    if (existingUser.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Check if username or email is already taken by someone else
    const [duplicateCheck] = await pool.query(
      'SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?', 
      [username, email, userId]
    );
    
    if (duplicateCheck.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Username or email already in use by another user'
      });
    }
    
    // Update the user
    await pool.query(`
      UPDATE users 
      SET username = ?,
          email = ?,
          role = ?,
          wallet = ?,
          has_lifetime_commission = ?,
          notes = ?
      WHERE id = ?
    `, [
      username,
      email,
      role,
      parseFloat(wallet) || 0,
      has_lifetime_commission ? 1 : 0,
      notes || null,
      userId
    ]);
    
    res.json({
      success: true,
      message: 'User updated successfully'
    });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// Route to delete a user
app.delete('/admin/users/:id/delete', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    
    // Check if user exists
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    
    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Don't allow admins to delete themselves
    if (userId == req.session.userId) {
      return res.status(400).json({
        success: false,
        message: 'You cannot delete your own account'
      });
    }
    
    // Delete user
    await pool.query('DELETE FROM users WHERE id = ?', [userId]);
    
    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// Route to create a new user
app.post('/admin/users/create', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { username, email, role, password, generate } = req.body;
    
    // Check if username or email already exists
    const [existingUsers] = await pool.query(
      'SELECT * FROM users WHERE username = ? OR email = ?',
      [username, email]
    );
    
    if (existingUsers.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Username or email already in use'
      });
    }
    
    // Generate password if requested
    let userPassword = password;
    if (generate) {
      // Generate a random password
      const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
      userPassword = "";
      for (let i = 0; i < 12; i++) {
        userPassword += chars.charAt(Math.floor(Math.random() * chars.length));
      }
    }
    
    // Validate password
    if (!userPassword || userPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long'
      });
    }
    
    // Hash the password
    const hashedPassword = await bcrypt.hash(userPassword, 10);
    
    // Create the user
    const [result] = await pool.query(`
      INSERT INTO users (
        username, 
        email, 
        password, 
        role, 
        created_at
      ) VALUES (?, ?, ?, ?, NOW())
    `, [
      username,
      email,
      hashedPassword,
      role
    ]);
    
    res.json({
      success: true, 
      message: 'User created successfully',
      userId: result.insertId,
      generatedPassword: generate ? userPassword : null
    });
  } catch (err) {
    console.error('Create user error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// Route to set a user's password (admin only)
app.post('/admin/users/:id/set-password', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { new_password } = req.body;
    
    // Validate the userId
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    
    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Validate password
    if (!new_password || new_password.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long'
      });
    }
    
    // Check if password has letters and numbers
    const hasLetters = /[A-Za-z]/.test(new_password);
    const hasNumbers = /[0-9]/.test(new_password);
    
    if (!hasLetters || !hasNumbers) {
      return res.status(400).json({
        success: false,
        message: 'Password must contain both letters and numbers'
      });
    }
    
    // Hash and update the password
    const hashedPassword = await bcrypt.hash(new_password, 10);
    await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId]);
    
    return res.json({
      success: true,
      message: `Password has been set successfully for user ${users[0].username}`
    });
  } catch (err) {
    console.error('Set user password error:', err);
    return res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});
// Admin settings route
app.get('/admin/settings', isAuthenticated, isAdmin, async (req, res) => {
  try {
    // Get all configuration settings
    const [configs] = await pool.query('SELECT * FROM config ORDER BY key_name ASC');
    
    res.render('admin/settings', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      configs: configs,
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Admin settings page error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Admin settings update route
app.post('/admin/settings/update', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { settings } = req.body;
    
    // Update each setting
    for (const [key, value] of Object.entries(settings)) {
      await pool.query('UPDATE config SET value = ? WHERE key_name = ?', [value, key]);
    }
    
    res.redirect('/admin/settings?success=Settings updated successfully');
  } catch (err) {
    console.error('Settings update error:', err);
    res.redirect('/admin/settings?error=Error updating settings');
  }
});

// Admin settings add route
app.post('/admin/settings/add', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { key_name, value, description } = req.body;
    
    // Check if key already exists
    const [existingKey] = await pool.query('SELECT * FROM config WHERE key_name = ?', [key_name]);
    
    if (existingKey.length > 0) {
      return res.redirect('/admin/settings?error=Setting key already exists');
    }
    
    // Add new setting
    await pool.query(
      'INSERT INTO config (key_name, value, description) VALUES (?, ?, ?)',
      [key_name, value, description]
    );
    
    res.redirect('/admin/settings?success=New setting added successfully');
  } catch (err) {
    console.error('Add setting error:', err);
    res.redirect('/admin/settings?error=Error adding new setting');
  }
});

// Admin settings delete route
app.post('/admin/settings/delete', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { key_name } = req.body;
    
    // Delete the setting
    await pool.query('DELETE FROM config WHERE key_name = ?', [key_name]);
    
    res.redirect('/admin/settings?success=Setting deleted successfully');
  } catch (err) {
    console.error('Delete setting error:', err);
    res.redirect('/admin/settings?error=Error deleting setting');
  }
});
// Route to set a user's password (admin only)
app.post('/admin/users/:id/set-password', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { new_password } = req.body;
    
    // Validate the userId
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    
    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Validate password
    if (!new_password || new_password.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long'
      });
    }
    
    // Check if password has letters and numbers
    const hasLetters = /[A-Za-z]/.test(new_password);
    const hasNumbers = /[0-9]/.test(new_password);
    
    if (!hasLetters || !hasNumbers) {
      return res.status(400).json({
        success: false,
        message: 'Password must contain both letters and numbers'
      });
    }
    
    // Hash and update the password
    const hashedPassword = await bcrypt.hash(new_password, 10);
    await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId]);
    
    return res.json({
      success: true,
      message: `Password has been set successfully for user ${users[0].username}`
    });
  } catch (err) {
    console.error('Set user password error:', err);
    return res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// Admin transactions route
app.get('/admin/transactions', isAuthenticated, isAdmin, async (req, res) => {
  try {
    // Get transactions with user information
    const [transactions] = await pool.query(`
      SELECT t.*, u.username 
      FROM transactions t
      JOIN users u ON t.user_id = u.id
      ORDER BY t.created_at DESC
      LIMIT 200
    `);
    
    // Get transaction statistics
    const [stats] = await pool.query(`
      SELECT 
        COUNT(*) as total_count,
        SUM(CASE WHEN type = 'payment' THEN 1 ELSE 0 END) as payment_count,
        SUM(CASE WHEN type = 'withdrawal' THEN 1 ELSE 0 END) as withdrawal_count,
        SUM(CASE WHEN type = 'commission' THEN 1 ELSE 0 END) as commission_count,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_count,
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count,
        SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_count
      FROM transactions
    `);
    
    res.render('admin/transactions', {
      user: {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      },
      transactions: transactions,
      stats: stats[0],
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Transactions page error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Process transaction route
app.post('/admin/transactions/:id/process', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const transactionId = req.params.id;
    const { status, notes } = req.body;
    
    // Get transaction details
    const [transactions] = await pool.query('SELECT * FROM transactions WHERE id = ?', [transactionId]);
    
    if (transactions.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found'
      });
    }
    
    const transaction = transactions[0];
    
    // Update transaction status
    await pool.query(
      'UPDATE transactions SET status = ?, notes = ?, updated_at = NOW() WHERE id = ?',
      [status, notes || transaction.notes, transactionId]
    );
    
    // If this is a withdrawal and it's completed, update the user's wallet balance
    if (transaction.type === 'withdrawal' && status === 'completed') {
      await pool.query(
        'UPDATE users SET wallet = wallet - ? WHERE id = ?',
        [transaction.amount, transaction.user_id]
      );
    }
    
    return res.json({
      success: true,
      message: `Transaction ${status}`
    });
  } catch (err) {
    console.error('Process transaction error:', err);
    return res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});
// Route for upgrading to lifetime commission
app.get('/upgrade-commission', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    
    // Check if user already has lifetime commission
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    const user = users[0];
    
    if (user.has_lifetime_commission) {
      return res.render('user/already-upgraded', { user });
    }
    
    // Get upgrade fee from config
    const upgradeFee = await getConfig('lifetime_commission_fee');
    const fee = parseFloat(upgradeFee);
    
    // Check if wallet balance is sufficient
    const hasEnoughBalance = parseFloat(user.wallet) >= fee;
    
    res.render('user/upgrade', { 
      user,
      upgradeFee: fee,
      hasEnoughBalance,
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Upgrade commission page error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// API route for processing the upgrade
app.post('/api/upgrade-commission', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    
    // Check if user already has lifetime commission
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    const user = users[0];
    
    if (user.has_lifetime_commission) {
      return res.json({
        success: false,
        message: 'You already have lifetime commission benefits'
      });
    }
    
    // Get upgrade fee from config
    const upgradeFee = parseFloat(await getConfig('lifetime_commission_fee'));
    
    // Check if user has enough balance in wallet
    if (parseFloat(user.wallet) < upgradeFee) {
      return res.json({
        success: false,
        message: 'Insufficient wallet balance. Please add funds to your wallet first.'
      });
    }
    
    // Begin transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // Deduct fee from wallet
      await connection.query(
        'UPDATE users SET wallet = wallet - ?, has_lifetime_commission = true WHERE id = ?',
        [upgradeFee, userId]
      );
      
      // Record the transaction
      await connection.query(`
        INSERT INTO transactions (
          user_id, type, amount, status, details
        ) VALUES (?, 'upgrade', ?, 'completed', ?)
      `, [
        userId,
        upgradeFee,
        'Lifetime commission upgrade via wallet balance'
      ]);
      
      await connection.commit();
      
      res.json({
        success: true,
        message: 'Upgrade successful! You now have lifetime commission benefits.'
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (err) {
    console.error('Upgrade commission error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// Route for individual product details
app.get('/products/:id', async (req, res) => {
  try {
    const productId = req.params.id;
    
    // Get product details
    const [products] = await pool.query(`
      SELECT p.*, u.username as merchant_name, u.business_name
      FROM links p
      JOIN users u ON p.merchant_id = u.id
      WHERE p.id = ? AND p.type = 'product' AND p.is_active = true
    `, [productId]);
    
    if (products.length === 0) {
      return res.status(404).render('error', { message: 'Product not found or no longer available.' });
    }
    
    const product = products[0];
    
    // Get product's merchant information
    const [merchants] = await pool.query(`
      SELECT id, username, business_name, business_description
      FROM users
      WHERE id = ?
    `, [product.merchant_id]);
    
    const merchant = merchants.length > 0 ? merchants[0] : null;
    
    // Check if this product has a referrer in the query (from shared links)
    let referrerUsername = null;
    if (req.query.ref) {
      const [sharedLinks] = await pool.query(`
        SELECT sl.*, u.username
        FROM shared_links sl
        JOIN users u ON sl.user_id = u.id
        WHERE sl.share_code = ?
      `, [req.query.ref]);
      
      if (sharedLinks.length > 0) {
        referrerUsername = sharedLinks[0].username;
      }
    }
    
    // Get cart count for authenticated user
    let cartCount = 0;
    if (req.session.userId) {
      const [cartItems] = await pool.query(`
        SELECT SUM(quantity) as count
        FROM cart_items
        WHERE user_id = ?
      `, [req.session.userId]);
      
      cartCount = cartItems[0].count || 0;
    }
    
    // Render the product details page
    res.render('user/product-details', {
      user: req.session.userId ? {
        id: req.session.userId,
        username: req.session.username,
        role: req.session.role
      } : null,
      product,
      merchant,
      referrerUsername,
      cartCount
    });
  } catch (err) {
    console.error('Product details error:', err);
    res.status(500).render('error', { message: 'Server error. Please try again later.' });
  }
});

// Withdrawal API endpoints
app.post('/api/withdraw', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { amount, gateway } = req.body;
    
    // Validate the amount
    if (!amount || isNaN(amount) || parseFloat(amount) <= 0) {
      return res.json({ success: false, message: 'Please enter a valid amount' });
    }
    
    // Get user information
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      return res.json({ success: false, message: 'User not found' });
    }
    
    const user = users[0];
    
    // Check if the user has enough balance
    if (parseFloat(user.wallet) < parseFloat(amount)) {
      return res.json({ success: false, message: 'Insufficient funds in your wallet' });
    }
    
    // Get minimum payout amount from config
    const minPayout = await getConfig('min_payout');
    if (parseFloat(amount) < parseFloat(minPayout)) {
      return res.json({ success: false, message: `Minimum withdrawal amount is $${minPayout}` });
    }
    
    // Check if user has provided bank details
    if (!user.account_number || !user.bank_code || !user.account_name) {
      return res.json({ success: false, message: 'Please update your bank account details in your profile first' });
    }
    
    // Create a withdrawal transaction - without gateway column
    const [result] = await pool.query(`
      INSERT INTO transactions (
        user_id, type, amount, status, details
      ) VALUES (?, ?, ?, ?, ?)
    `, [
      userId,
      'withdrawal',
      parseFloat(amount),
      'pending',
      `Withdrawal request via ${gateway}`
    ]);
    
    // Deduct the amount from the user's wallet
    await pool.query(`
      UPDATE users SET wallet = wallet - ? WHERE id = ?
    `, [parseFloat(amount), userId]);
    
    return res.json({ success: true, message: 'Withdrawal request submitted successfully' });
  } catch (err) {
    console.error('Withdrawal request error:', err);
    return res.json({ success: false, message: 'Server error. Please try again later.' });
  }
});

// Manual withdrawal API endpoint
app.post('/api/withdraw-manual', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { amount, gateway } = req.body;
    
    // Validate the amount
    if (!amount || isNaN(amount) || parseFloat(amount) <= 0) {
      return res.json({ success: false, message: 'Please enter a valid amount' });
    }
    
    // Get user information
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      return res.json({ success: false, message: 'User not found' });
    }
    
    const user = users[0];
    
    // Check if the user has enough balance
    if (parseFloat(user.wallet) < parseFloat(amount)) {
      return res.json({ success: false, message: 'Insufficient funds in your wallet' });
    }
    
    // Get minimum payout amount from config
    const minPayout = await getConfig('min_payout');
    if (parseFloat(amount) < parseFloat(minPayout)) {
      return res.json({ success: false, message: `Minimum withdrawal amount is $${minPayout}` });
    }
    
    // Check if user has provided bank details
    if (!user.account_number || !user.bank_code || !user.account_name) {
      return res.json({ success: false, message: 'Please update your bank account details in your profile first' });
    }
    
    // Create a withdrawal transaction - without gateway column
    const [result] = await pool.query(`
      INSERT INTO transactions (
        user_id, type, amount, status, details
      ) VALUES (?, ?, ?, ?, ?)
    `, [
      userId,
      'withdrawal',
      parseFloat(amount),
      'pending',
      `Manual withdrawal request to ${user.bank_code}, Account: ${user.account_number}, Name: ${user.account_name}`
    ]);
    
    // Deduct the amount from the user's wallet
    await pool.query(`
      UPDATE users SET wallet = wallet - ? WHERE id = ?
    `, [parseFloat(amount), userId]);
    
    return res.json({ success: true, message: 'Withdrawal request submitted successfully. Your request will be reviewed by admin.' });
  } catch (err) {
    console.error('Manual withdrawal request error:', err);
    return res.json({ success: false, message: 'Server error. Please try again later.' });
  }
});
app.listen(PORT, async () => {
  try {
    await initializeDatabase();
    console.log(`Server running on port ${PORT}`);
  } catch (err) {
    console.error('Server startup error:', err);
  }
}
);