# Module Management System

A comprehensive e-learning module management system built with Node.js, Express, and SQLite.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Setup Instructions](#setup-instructions)
  - [Environment Variables](#environment-variables)
  - [Database Setup](#database-setup)
  - [Admin Account](#admin-account)
- [Running the Application](#running-the-application)
- [Security Features](#security-features)
- [Usage Guidelines](#usage-guidelines)
  - [For Regular Users](#for-regular-users)
  - [For Administrators](#for-administrators)
- [API Endpoints](#api-endpoints)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)

## Features

- Upload and manage e-learning modules (SCORM, HTML, PDF, etc.)
- Admin authentication with JWT tokens and username/password login
- Responsive web interface with modern UI and animated bubble backgrounds
- Secure file handling and validation
- Module organization and categorization
- Real-time upload progress tracking
- Rate limiting for enhanced security against bots
- Customizable favicon matching the brand identity

## Installation

### Prerequisites

- Node.js (v20 or higher)
- npm (v8 or higher)
- Git (for cloning the repository)

### Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd module-management-system
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure environment variables:**
   Create a `.env` file in the root directory with the following variables:
   ```
   PORT=3000
   JWT_SECRET=your_secure_jwt_secret_here
   ADMIN_SECRET_KEY=your_admin_secret_key_here
   ```
   
   You can generate secure keys using:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

4. **Database Setup:**
   The application uses SQLite for data storage. Initialize the database schema:
   ```bash
   npm run migrate
   ```
   
   This will create the database file (`dev.db`) and set up the required tables:
   - `User` table for admin authentication
   - `UploadHistory` table for tracking file uploads
   
   **Database Schema Details:**
   - User table: `id`, `username`, `password` (hashed), `createdAt`, `updatedAt`
   - UploadHistory table: `id`, `moduleName`, `fileName`, `fileSize`, `uploadTimestamp`, `uploader`
   
   **Database Management Commands:**
   ```bash
   # Check current database status
   npm run migrate status
   
   # Create a new migration after schema changes
   npm run migrate dev
   
   # Apply migrations in production
   npm run migrate:deploy
   ```

5. **Create an admin user:**
   The system automatically creates an initial admin user on first run:
   - Username: admin
   - Password: admin123
   
   **Important:** Change this password immediately after first login for security.

6. **Start the application:**
   ```bash
   npm start
   ```

### Running the Application

Start the development server:
```bash
npm start
```

Or for production:
```bash
npm run production
```

### Running with Docker

**Note:** Docker images use Node.js 20-alpine to ensure compatibility with Prisma 7.

1. **Build and run with Docker Compose:**
   ```bash
   docker-compose up -d
   ```

2. **Build and run with Docker only:**
   ```bash
   # Build the image
   docker build -t module-management .
   
   # Run the container
   docker run -d \
     -p 3000:3000 \
     -v $(pwd)/uploads:/app/uploads \
     -v $(pwd)/modules:/app/modules \
     -v $(pwd)/dev.db:/app/dev.db \
     --name module-management \
     module-management
   ```

### Access the Application

- Home page: http://localhost:3000
- Admin login: http://localhost:3000/admin/login
- API documentation: http://localhost:3000/api/docs

## Security Features

### Authentication & Authorization
- JWT-based authentication for admin panel with 24-hour token expiration
- Username/password login with bcrypt password hashing
- Protected admin routes with authentication middleware
- Session management with secure token handling

### File Security
- Comprehensive file type validation for uploads (ZIP only)
- Malware scanning for dangerous file extensions (.php, .asp, .jsp, etc.)
- Sanitized file names to prevent directory traversal attacks
- Secure file serving with proper MIME types
- Upload size limits (500MB) to prevent abuse
- Blocked upload history tracking for security auditing

### API Security
- Protected admin routes with authentication middleware
- Input validation on all endpoints
- Rate limiting on upload and authentication endpoints
- Upload rate limiting (10 requests per hour per IP) to prevent bot abuse
- Prepared statements to prevent SQL injection
- Secure HTTP headers (when configured at reverse proxy level)

### Best Practices
- Environment variables for sensitive configuration
- Secure key generation for JWT secrets
- Proper error handling without exposing sensitive information
- Logging of security events and blocked uploads
- Regular security audits and updates

## Create Admin Credentials
To change the admin password, use the provided script:
```bash
node create-admin.js
```
### Changing Password
To change the admin password, use the provided script:
```bash
node change-password.js newpassword123
```

### Admin Password Management

#### Changing Password
To change the admin password, use the provided script:
```bash
node change-password.js newpassword123
```

You can also change the password through the admin panel after logging in.

#### Changing JWT Secret
Update the JWT_SECRET value in your `.env` file. Note that this will invalidate all existing sessions.

#### Manual Password Reset
If you need to manually reset the admin password in the database:
```bash
node -e "const bcrypt = require('bcryptjs'); console.log(bcrypt.hashSync('newpassword', 10));" 
```

Then update the password hash in the User table:
```sql
UPDATE User SET password = 'hashed_password_here' WHERE username = 'admin';
```

## Usage Guidelines

### For Regular Users
- Visit the home page to browse available modules
- Click on any module to access its content
- Use the modules page to view all available learning materials
- Access modules from any device (responsive design)

### For Administrators
- Navigate to the admin login page (`/admin/login`)
- Log in with admin credentials
- Upload new modules using the admin panel (ZIP files only)
- Manage existing modules (rename, delete)
- View upload history including blocked attempts
- Monitor system statistics and module counts
- Change admin password regularly for security

### Module Management
- Upload modules as ZIP files containing course content
- System automatically extracts and organizes content
- Supports various content types (HTML, PDF, SCORM, videos)
- Automatic indexing of module contents
- Malware scanning for all uploads
- Upload history tracking for auditing

## API Endpoints

### Public Endpoints
- `GET /` - Home page
- `GET /modules` - Modules listing page
- `GET /modules/:moduleName/*` - Access module content
- `GET /admin/login` - Admin login page
- `POST /api/admin/login` - Admin authentication
- `POST /api/admin/logout` - Admin logout

### Admin-Only Endpoints
- `GET /admin` - Admin dashboard
- `GET /api/modules` - List all modules
- `POST /api/upload` - Upload new module
- `POST /api/delete` - Delete module
- `POST /api/rename` - Rename module
- `GET /api/upload-history` - Get upload history
- `DELETE /api/upload-history/:id` - Delete upload history record
- `GET /api/recent-module` - Get most recently uploaded module

## Deployment

### Production Deployment

1. **Configure environment variables for production:**
   ```
   NODE_ENV=production
   PORT=3000
   JWT_SECRET=your_production_secret_here
   ADMIN_SECRET_KEY=your_admin_secret_key_here
   ```

2. **Run with a process manager (PM2 recommended):**
   ```bash
   npm install -g pm2
   pm2 start server.js --name module-management
   pm2 startup
   pm2 save
   ```

3. **Or run with Docker (recommended for containerized environments):**
   ```bash
   docker-compose up -d
   ```

4. **Set up automatic backups:**
   ```bash
   # Add to crontab for daily backups
   0 2 * * * /usr/bin/sqlite3 /path/to/dev.db .dump > /path/to/backups/dev-$(date +\%Y\%m\%d).sql
   ```
   
   **Database Backup and Recovery:**
   
   To backup the database:
   ```bash
   sqlite3 dev.db .dump > backup-$(date +%Y%m%d).sql
   ```
   
   To restore from a backup:
   ```bash
   # Remove the current database
   rm dev.db
   
   # Restore from backup
   sqlite3 dev.db < backup-file.sql
   
   # Run migrations to ensure schema is up to date
   npm run migrate
   ```
   
   **Direct Database Access:**
   
   To directly access the database for queries or troubleshooting:
   ```bash
   sqlite3 dev.db
   ```
   
   Common queries:
   ```sql
   -- List all users
   SELECT * FROM User;
   
   -- List recent uploads
   SELECT * FROM UploadHistory ORDER BY uploadTimestamp DESC LIMIT 10;
   
   -- Count total modules
   SELECT COUNT(*) FROM UploadHistory WHERE moduleName NOT LIKE 'BLOCKED_%';
   ```

### Security Recommendations

- Use a firewall (ufw recommended)
- Keep Node.js and dependencies updated
- Regularly rotate JWT secrets
- Monitor logs for suspicious activity
- Restrict file upload permissions
- Use strong admin passwords
- Implement additional security headers at the reverse proxy level

## Contributing

We welcome contributions to improve the Module Management System!

### How to Contribute

1. **Fork the Repository**
   Click the "Fork" button at the top right of this repository.

2. **Clone Your Fork**
   ```bash
   git clone https://github.com/your-username/module-management-system.git
   cd module-management-system
   ```

3. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make Your Changes**
   - Follow the existing code style
   - Add tests if applicable
   - Update documentation as needed

5. **Commit Your Changes**
   ```bash
   git commit -m "Add feature: brief description of your changes"
   ```

6. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Open a Pull Request**
   Go to the original repository and open a pull request with a clear description of your changes.

### Reporting Issues

- Use the GitHub issue tracker to report bugs
- Include steps to reproduce the issue
- Provide information about your environment (OS, Node.js version, etc.)
- Be as descriptive as possible

### Code Style Guidelines

- Follow JavaScript Standard Style
- Use meaningful variable and function names
- Comment complex logic
- Keep functions small and focused
- Write modular, reusable code

## GitHub Repository

To push this project to your own GitHub repository:

1. **Create a new repository on GitHub**
   - Go to GitHub and create a new repository
   - Don't initialize with a README

2. **Initialize Git in your local project**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   ```

3. **Connect to your GitHub repository**
   ```bash
   git remote add origin https://github.com/your-username/your-repository-name.git
   git branch -M main
   git push -u origin main
   ```

4. **Set up GitHub Actions (optional)**
   Create `.github/workflows/node.js.yml` for automated testing:
   ```yaml
   name: Node.js CI
   
   on:
     push:
       branches: [ main ]
     pull_request:
       branches: [ main ]
   
   jobs:
     build:
       runs-on: ubuntu-latest
       
       strategy:
         matrix:
           node-version: [14.x, 16.x, 18.x]
       
       steps:
       - uses: actions/checkout@v3
       - name: Use Node.js ${{ matrix.node-version }}
         uses: actions/setup-node@v3
         with:
           node-version: ${{ matrix.node-version }}
       - run: npm ci
       - run: npm test
   ```

## License

This project is licensed under the MIT License.