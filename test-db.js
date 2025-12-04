const sqlite3 = require('sqlite3').verbose();

// Open the database
const db = new sqlite3.Database('./dev.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to the SQLite database.');
    
    // Query the database for the user
    db.get('SELECT * FROM User WHERE username = ?', ['admin'], (err, user) => {
      if (err) {
        console.error('Error querying database:', err.message);
      } else {
        console.log('User found:', user);
      }
      
      // Close the database
      db.close((err) => {
        if (err) {
          console.error('Error closing database:', err.message);
        } else {
          console.log('Database connection closed.');
        }
      });
    });
  }
});