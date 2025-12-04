const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

// Get the new password from command line arguments
const newPassword = process.argv[2];

if (!newPassword) {
    console.log('Usage: node change-password.js <new-password>');
    process.exit(1);
}

// Open the database
const db = new sqlite3.Database('./dev.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
        process.exit(1);
    } else {
        console.log('Connected to the SQLite database.');
    }
});

// Hash the new password
const saltRounds = 10;
bcrypt.hash(newPassword, saltRounds, (err, hash) => {
    if (err) {
        console.error('Error hashing password:', err.message);
        db.close();
        return;
    }

    // Update the admin user's password
    const stmt = db.prepare('UPDATE User SET password = ?, updatedAt = CURRENT_TIMESTAMP WHERE username = "admin"');
    
    stmt.run(hash, function(err) {
        if (err) {
            console.error('Error updating password:', err.message);
        } else if (this.changes > 0) {
            console.log('Admin password updated successfully!');
        } else {
            console.log('Admin user not found. No password was updated.');
        }
    });
    
    stmt.finalize();
    
    // Close the database connection
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err.message);
        } else {
            console.log('Database connection closed.');
        }
    });
});