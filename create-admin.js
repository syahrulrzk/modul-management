const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

// Open the database
const db = new sqlite3.Database('./dev.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to the SQLite database.');
  }
});

// Create the users table if it doesn't exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS User (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) {
      console.error('Error creating table:', err.message);
    } else {
      console.log('User table ready.');
    }
  });

  // Hash the password
  const saltRounds = 10;
  bcrypt.hash('admin123', saltRounds, (err, hash) => {
    if (err) {
      console.error('Error hashing password:', err.message);
      return;
    }

    // Insert or update the admin user
    const stmt = db.prepare(`INSERT OR REPLACE INTO User (id, username, password, createdAt, updatedAt) 
                             VALUES ((SELECT id FROM User WHERE username = 'admin'), 'admin', ?, 
                                     COALESCE((SELECT createdAt FROM User WHERE username = 'admin'), CURRENT_TIMESTAMP), 
                                     CURRENT_TIMESTAMP)`);
    
    stmt.run(hash, function(err) {
      if (err) {
        console.error('Error inserting user:', err.message);
      } else {
        console.log(`Admin user created/updated with ID: ${this.lastID || this.changes}`);
        console.log('Username: admin');
        console.log('Password: admin123');
        console.log('(Remember to change this password after first login)');
      }
    });
    
    stmt.finalize();
  });
});

// Close the database connection after a delay to ensure all operations complete
setTimeout(() => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database connection closed.');
    }
  });
}, 1000);