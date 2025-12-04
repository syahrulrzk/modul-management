require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const AdmZip = require('adm-zip');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for rate limiting when behind a reverse proxy
app.set('trust proxy', 1);

// Security headers middleware (all security headers removed as requested)
// Will be implemented at Nginx level instead
app.use((req, res, next) => {
  next();
});



// Initialize SQLite database
const db = new sqlite3.Database('./dev.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database');
  }
});

// Close database connection on exit
process.on('exit', () => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database connection closed.');
    }
  });
});

// Handle Ctrl+C gracefully
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database connection closed.');
    }
    process.exit(0);
  });
});

// Increase payload limits for large files
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ limit: '500mb', extended: true }));

// Authentication middleware for admin routes
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Reusable template function for default module pages
function generateModulePageTemplate(moduleName, files) {
  return `<!DOCTYPE html>
<html>
<head>
    <title>${moduleName}</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: '#6366f1',
                        secondary: '#8b5cf6',
                        dark: '#0f172a',
                    }
                }
            }
        }
    </script>
    <style>

        
        body {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f0f23 100%);
            min-height: 100vh;
            font-family: 'Poppins', sans-serif;
        }
        
        .glass-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.18);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        }
        
        .module-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #8b5cf6, #6366f1);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1rem;
        }
        
        /* Responsive behavior */
        @media (max-width: 768px) {
            .p-8 {
                padding: 1rem;
            }
            
            .text-3xl {
                font-size: 1.875rem;
            }
            
            .mb-6 {
                margin-bottom: 1rem;
            }
            
            .grid {
                gap: 0.5rem;
            }
            
            .p-4 {
                padding: 0.75rem;
            }
        }
        
        @media (max-width: 480px) {
            .p-8 {
                padding: 0.75rem;
            }
            
            .text-3xl {
                font-size: 1.5rem;
            }
            
            .mb-2 {
                margin-bottom: 0.5rem;
            }
            
            .mb-6 {
                margin-bottom: 0.75rem;
            }
            
            .px-6 {
                padding-left: 1rem;
                padding-right: 1rem;
            }
            
            .py-3 {
                padding-top: 0.75rem;
                padding-bottom: 0.75rem;
            }
        }
    </style>
</head>
<body class="text-white">
    <div class="min-h-screen flex items-center justify-center p-4">
        <div class="glass-card rounded-2xl p-8 max-w-2xl w-full">
            <div class="mb-8 text-center">
                <div class="module-icon mb-6 mx-auto">
                    <i class="fas fa-book-open text-3xl"></i>
                </div>
                <h1 class="text-3xl font-bold mb-2 flex items-center justify-center w-full">
                    <i class="fas fa-graduation-cap mr-3 text-purple-400"></i>
                    <span>Welcome to ${moduleName.replace(/-/g, ' ').replace(/\w\S*/g, (txt) => txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase())}</span>
                </h1>
                <p class="text-gray-300 mb-6 text-center w-full mx-auto">Learning Module</p>
                <div class="inline-block bg-purple-900/50 px-4 py-2 rounded-full mb-6">
                    <span class="text-purple-400"><i class="fas fa-info-circle mr-2"></i>Default Module Viewer</span>
                </div>
            </div>
            
            <div class="mb-8 text-center">
                <h2 class="text-xl font-semibold mb-4 flex items-center justify-center w-full">
                    <i class="fas fa-folder-open mr-2 text-purple-400"></i>
                    Module Contents
                </h2>
                <p class="text-gray-400 mb-6 text-center">You can explore the module contents using the links below:</p>
                
                <div class="grid grid-cols-1 gap-3">
                  ${files.map(file => `
                    <a href="${file}" class="glass-card p-4 rounded-lg flex items-center justify-center hover:bg-white/10 transition w-full">
                        <i class="fas fa-${path.extname(file).toLowerCase() === '.pdf' ? 'file-pdf' : path.extname(file).toLowerCase() === '.mp4' || path.extname(file).toLowerCase() === '.avi' || path.extname(file).toLowerCase() === '.mov' || path.extname(file).toLowerCase() === '.mkv' ? 'file-video' : path.extname(file).toLowerCase() === '.zip' ? 'file-archive' : path.extname(file).toLowerCase() === '.html' || path.extname(file).toLowerCase() === '.htm' ? 'file-code' : 'file'} mr-3 text-purple-400"></i>
                        <span>${file}</span>
                    </a>
                  `).join('')}
                </div>
            </div>
            
            <div class="text-center">
                <a href="/modules" class="inline-flex items-center bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 px-6 py-3 rounded-lg transition transform hover:-translate-y-0.5 shadow-lg">
                    <i class="fas fa-arrow-left mr-2"></i>
                    Back to Modules
                </a>
            </div>
        </div>
    </div>
</body>
</html>`;
}

// Configure multer for file uploads with larger limits
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/')
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname)
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 500 * 1024 * 1024 // 500 MB in bytes
  }
});

// Rate limiter for upload endpoint - max 10 requests per hour per IP
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // limit each IP to 10 requests per windowMs
  message: {
    error: 'Too many upload attempts, please try again later.'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Serve static files for frontend (moved to the beginning to ensure static files are served correctly)
app.use(express.static('public'));

// Serve static files from modules directory
app.use('/modules', express.static(path.join(__dirname, 'modules')));

// Serve landing page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve modules page
app.get('/modules', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'modules.html'));
});

// Serve admin login page
app.get('/admin/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve admin dashboard
app.get('/admin', (req, res) => {
  // Check if user is authenticated via session or token
  // For simplicity, we'll serve the admin page and handle auth on client-side
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Middleware to parse JSON
app.use(express.json());

// Create necessary directories
const dirs = ['uploads', 'modules'];
dirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir);
  }
});

// Serve module files with auto-index capability
app.get('/modules/:moduleName/*', (req, res) => {
  const moduleName = req.params.moduleName;
  const modulePath = path.join(__dirname, 'modules', moduleName);
  
  // Check if module exists
  if (!fs.existsSync(modulePath)) {
    return res.status(404).send('Module not found');
  }
  
  // Security check: Prevent access to dangerous files
  const requestedPath = req.params[0] || '';
  const fullPath = path.join(modulePath, requestedPath);
  
  // Check if the requested path is within the module directory (prevent directory traversal)
  if (!fullPath.startsWith(modulePath + path.sep) && fullPath !== modulePath) {
    return res.status(403).send('Access denied');
  }
  
  // Check file extension for dangerous types
  const dangerousExtensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py', '.sh', '.exe', '.bat', '.cmd'];
  const fileExt = path.extname(fullPath).toLowerCase();
  
  if (dangerousExtensions.includes(fileExt)) {
    return res.status(403).send('Access to this file type is forbidden for security reasons');
  }
  
  // If requesting a specific file, serve it directly
  if (req.params[0]) {
    const filePath = path.join(modulePath, req.params[0]);
    if (fs.existsSync(filePath)) {
      return res.sendFile(filePath);
    }
  }
  
  // Try different index files in the root and nested directory
  const indexPaths = [
    path.join(modulePath, 'index.html'),
    path.join(modulePath, 'index.htm'),
    path.join(modulePath, 'index_scorm.html'),
    path.join(modulePath, 'goodbye.html'),
    path.join(modulePath, moduleName, 'index.html'),
    path.join(modulePath, moduleName, 'index.htm'),
    path.join(modulePath, moduleName, 'index_scorm.html'),
    path.join(modulePath, moduleName, 'goodbye.html')
  ];
  
  for (const indexPath of indexPaths) {
    if (fs.existsSync(indexPath)) {
      return res.sendFile(indexPath);
    }
  }
  
  // If no index file found, check for any HTML file
  let files = [];
  try {
    files = fs.readdirSync(modulePath);
    
    // Security check: Filter out dangerous files from the listing
    const dangerousExtensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py', '.sh', '.exe', '.bat', '.cmd'];
    files = files.filter(file => {
      const ext = path.extname(file).toLowerCase();
      return !dangerousExtensions.includes(ext);
    });
  } catch (err) {
    // If we can't read the root directory, try the nested directory
    try {
      files = fs.readdirSync(path.join(modulePath, moduleName));
      // Security check: Filter out dangerous files from the listing
      const dangerousExtensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py', '.sh', '.exe', '.bat', '.cmd'];
      files = files.filter(file => {
        const ext = path.extname(file).toLowerCase();
        return !dangerousExtensions.includes(ext);
      });
      // If successful, serve from the nested directory
      const nestedPath = path.join(modulePath, moduleName);
      const htmlFiles = files.filter(file => path.extname(file).toLowerCase() === '.html');
      if (htmlFiles.length > 0) {
        return res.sendFile(path.join(nestedPath, htmlFiles[0]));
      }
    } catch (nestedErr) {
      // Create a default index.html if no HTML files found
      const defaultIndexPath = path.join(modulePath, 'index.html');
      const defaultContent = generateModulePageTemplate(moduleName, files);
      fs.writeFileSync(defaultIndexPath, defaultContent);
      return res.sendFile(defaultIndexPath);
    }
  }
  
  // Check for HTML files in the root directory
  const htmlFiles = files.filter(file => path.extname(file).toLowerCase() === '.html');
  if (htmlFiles.length > 0) {
    return res.sendFile(path.join(modulePath, htmlFiles[0]));
  }
  
  // Check for HTML files in the nested directory (common ZIP structure)
  if (files.includes(moduleName)) {
    try {
      const nestedFiles = fs.readdirSync(path.join(modulePath, moduleName));
      // Security check: Filter out dangerous files from the listing
      const dangerousExtensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py', '.sh', '.exe', '.bat', '.cmd'];
      const filteredFiles = nestedFiles.filter(file => {
        const ext = path.extname(file).toLowerCase();
        return !dangerousExtensions.includes(ext);
      });
      const nestedHtmlFiles = filteredFiles.filter(file => path.extname(file).toLowerCase() === '.html');
      if (nestedHtmlFiles.length > 0) {
        return res.sendFile(path.join(modulePath, moduleName, nestedHtmlFiles[0]));
      }
    } catch (err) {
      // Continue to default index creation
    }
  }
  
  // Create a default index.html if no HTML files found
  const defaultIndexPath = path.join(modulePath, 'index.html');
  const defaultContent = generateModulePageTemplate(moduleName, files);
  fs.writeFileSync(defaultIndexPath, defaultContent);
  return res.sendFile(defaultIndexPath);
});

// API Routes

// GET /api/modules - List all modules
app.get('/api/modules', (req, res) => {
  fs.readdir('modules', (err, files) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to read modules directory' });
    }
    
    // Filter out only directories (modules)
    const modules = files.filter(file => {
      return fs.statSync(path.join('modules', file)).isDirectory();
    });
    
    res.json({ modules });
  });
});

// GET /api/recent-module - Get the most recently uploaded module
app.get('/api/recent-module', (req, res) => {
  fs.readdir('modules', (err, files) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to read modules directory' });
    }
    
    // Filter out only directories (modules)
    const modules = files.filter(file => {
      return fs.statSync(path.join('modules', file)).isDirectory();
    });
    
    if (modules.length === 0) {
      return res.json({ module: null });
    }
    
    // Get the most recently modified module
    let recentModule = null;
    let recentTime = 0;
    
    modules.forEach(module => {
      const modulePath = path.join('modules', module);
      const stats = fs.statSync(modulePath);
      if (stats.mtimeMs > recentTime) {
        recentTime = stats.mtimeMs;
        recentModule = module;
      }
    });
    
    res.json({ module: recentModule });
  });
});

// POST /api/upload - Upload and extract a new module
app.post('/api/upload', uploadLimiter, authenticateAdmin, upload.single('module'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  // Security check: Ensure uploaded file is a ZIP file
  if (req.file.mimetype !== 'application/zip' && 
      req.file.mimetype !== 'application/x-zip-compressed' && 
      !req.file.originalname.toLowerCase().endsWith('.zip')) {
    // Remove the uploaded file
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ 
      error: 'Invalid file type. Only ZIP files are allowed.',
      details: 'File must be a ZIP archive'
    });
  }
  
  // Get custom module name from form data, fallback to file name if not provided
  let moduleName = req.body.moduleName || path.parse(req.file.originalname).name;
  
  // Sanitize module name to handle spaces and special characters
  moduleName = moduleName
    .replace(/\s+/g, '-')
    .replace(/[^a-zA-Z0-9\-_\.]/g, '')
    .toLowerCase();
  
  const zipPath = req.file.path;
  const modulePath = path.join('modules', moduleName);
  
  try {
    // Create module directory
    if (!fs.existsSync(modulePath)) {
      fs.mkdirSync(modulePath, { recursive: true });
    }
    
    // Extract ZIP file
    const zip = new AdmZip(zipPath);
    const zipEntries = zip.getEntries();
    
    // Security check: Scan for dangerous file types
    const dangerousExtensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py', '.sh', '.exe', '.bat', '.cmd'];
    const dangerousFiles = [];
    
    zipEntries.forEach(entry => {
      const ext = path.extname(entry.entryName).toLowerCase();
      if (dangerousExtensions.includes(ext)) {
        dangerousFiles.push(entry.entryName);
      }
    });
    
    if (dangerousFiles.length > 0) {
      // Remove the uploaded file and created directory
      fs.unlinkSync(zipPath);
      if (fs.existsSync(modulePath)) {
        fs.rm(modulePath, { recursive: true }, () => {});
      }
      
      // Record blocked upload in history
      const fileSize = req.file.size || 0;
      const uploader = req.user ? req.user.username : 'unknown';
      
      db.run(
        'INSERT INTO UploadHistory (moduleName, fileName, fileSize, uploader) VALUES (?, ?, ?, ?)',
        [`BLOCKED_${Date.now()}_${moduleName}`, req.file.originalname, fileSize, uploader],
        (err) => {
          if (err) {
            console.error('Failed to record blocked upload history:', err.message);
          }
        }
      );
      
      return res.status(400).json({
        error: 'Security violation: Dangerous file types detected',
        details: 'The following dangerous files were found in the ZIP: ' + dangerousFiles.join(', '),
        forbiddenTypes: dangerousExtensions
      });
    }
    
    // Extract ZIP file if all checks pass
    zip.extractAllTo(modulePath, true);
    
    // Remove uploaded ZIP file
    fs.unlinkSync(zipPath);
    
    // Record upload history
    const fileSize = req.file.size || 0;
    const uploader = req.user ? req.user.username : 'unknown';
    
    db.run(
      'INSERT INTO UploadHistory (moduleName, fileName, fileSize, uploader) VALUES (?, ?, ?, ?)',
      [moduleName, req.file.originalname, fileSize, uploader],
      (err) => {
        if (err) {
          console.error('Failed to record upload history:', err.message);
        }
      }
    );
    
    res.json({ 
      success: true, 
      message: 'Module uploaded and extracted successfully',
      moduleName: moduleName
    });
  } catch (err) {
    console.error('Extraction error:', err);
    
    // Clean up on error
    if (fs.existsSync(zipPath)) {
      fs.unlinkSync(zipPath);
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'Failed to extract module',
      details: err.message,
      stack: err.stack
    });
  }
});

// POST /api/delete - Delete a module
app.post('/api/delete', authenticateAdmin, (req, res) => {
  try {
    const { moduleName } = req.body;
    
    if (!moduleName) {
      return res.status(400).json({ error: 'Module name is required' });
    }
    
    const modulePath = path.join('modules', moduleName);
    
    // Check if module exists
    if (!fs.existsSync(modulePath)) {
      return res.status(404).json({ error: 'Module not found' });
    }
    
    // Remove module directory
    fs.rm(modulePath, { recursive: true }, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to delete module' });
      }
      
      res.json({ 
        success: true, 
        message: 'Module deleted successfully'
      });
    });
  } catch (err) {
    console.error('Deletion error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to delete module',
      details: err.message,
      stack: err.stack
    });
  }
});

// GET /api/upload-history - Get upload history
app.get('/api/upload-history', authenticateAdmin, (req, res) => {
  db.all('SELECT * FROM UploadHistory ORDER BY uploadTimestamp DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to retrieve upload history' });
    }
    
    res.json({ history: rows });
  });
});



// POST /api/rename - Rename a module
app.post('/api/rename', authenticateAdmin, (req, res) => {
  try {
    const { oldName, newName } = req.body;
    
    if (!oldName || !newName) {
      return res.status(400).json({ error: 'Both old and new module names are required' });
    }
    
    // Sanitize new module name
    const sanitizedNewName = newName
      .replace(/\s+/g, '-')
      .replace(/[^a-zA-Z0-9\-_\.]/g, '')
      .toLowerCase();
    
    if (!sanitizedNewName) {
      return res.status(400).json({ error: 'Invalid new module name' });
    }
    
    const oldModulePath = path.join('modules', oldName);
    const newModulePath = path.join('modules', sanitizedNewName);
    
    // Check if old module exists
    if (!fs.existsSync(oldModulePath)) {
      return res.status(404).json({ error: 'Module not found' });
    }
    
    // Check if new module name already exists
    if (fs.existsSync(newModulePath)) {
      return res.status(409).json({ error: 'A module with that name already exists' });
    }
    
    // Rename module directory
    fs.rename(oldModulePath, newModulePath, (err) => {
      if (err) {
        console.error('Rename error:', err);
        return res.status(500).json({ error: 'Failed to rename module' });
      }
      
      res.json({ 
        success: true, 
        message: 'Module renamed successfully',
        newName: sanitizedNewName
      });
    });
  } catch (err) {
    console.error('Rename error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to rename module',
      details: err.message,
      stack: err.stack
    });
  }
});

// Serve landing page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve modules page
app.get('/modules', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'modules.html'));
});

// Serve admin login page
app.get('/admin/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve admin dashboard
app.get('/admin', (req, res) => {
  // Check if user is authenticated via session or token
  // For simplicity, we'll serve the admin page and handle auth on client-side
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Admin login endpoint
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  // Query the database for the user
  db.get('SELECT * FROM User WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Compare the provided password with the hashed password
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Password comparison error' });
      }
      
      if (!result) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Generate JWT token
      const token = jwt.sign(
        { id: user.id, username: user.username },
        process.env.JWT_SECRET || 'fallback_secret_key',
        { expiresIn: '24h' }
      );
      
      return res.json({
        success: true,
        message: 'Authentication successful',
        token: token,
        redirect: '/admin'
      });
    });
  });
});

// Admin logout endpoint
app.post('/api/admin/logout', (req, res) => {
  // For JWT, logout is typically handled client-side by removing the token
  // But we can provide an endpoint for future server-side token blacklisting
  return res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Module Management System running on http://0.0.0.0:${PORT}`);
});

// Handle server errors
server.on('error', (err) => {
  console.error('Server error:', err);
});