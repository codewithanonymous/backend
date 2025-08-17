const express = require('express');
const http = require('http');
const path = require('path');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const fs = require('fs');
require('dotenv').config();

// Import our custom modules with PostgreSQL support
const db = require('./db-pg');
const { initSocket, emitNewSnap } = require('./socket');

// JWT Secret from environment
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const cors = require('cors')

// At the top with other requires
const cors = require('cors');

// After creating Express app
const app = express();

// CORS Configuration
const allowedOrigins = [
    'https://kitsflick-frontend.onrender.com',
    'http://localhost:3000'
];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Handle pre-flight requests
app.options('*', cors(corsOptions));


// 2. Set up middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../frontend')));

// 3. Create HTTP server after Express setup
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// 4. Initialize Socket.IO after server is created
initSocket(server);

// Rest of your routes and server logic...


// Request logging middleware
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
    console.log('Body:', req.body);
    console.log('Query:', req.query);
    console.log('Content-Type:', req.get('Content-Type'));
    console.log('User-Agent:', req.get('User-Agent'));
    next();
});

// --- File Upload Setup ---
const uploadDir = path.join(__dirname, '../frontend', 'uploads');

// Create uploads directory if it doesn't exist
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const fileExt = path.extname(file.originalname).toLowerCase();
        const newFilename = `${uuidv4()}${fileExt}`;
        cb(null, newFilename);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPG, PNG, and GIF are allowed.'));
        }
    }
});

// --- Helper Functions ---
const handleDatabaseError = (res, error) => {
    console.error('Database error:', error);
    res.status(500).json({
        success: false,
        message: 'A database error occurred',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- Routes ---

// Serve the index page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend', 'index.html'));
});

// Serve the upload page
app.get('/upload', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend', 'upload.html'));
});

// Serve the feed page
app.get('/feed', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend', 'feed.html'));
});

// User registration
app.post('/api/signup', async (req, res) => {
    try {
        console.log('=== SIGNUP REQUEST RECEIVED ===');
        console.log('Request body:', JSON.stringify(req.body, null, 2));
        
        const { username, email, password } = req.body;
        
        if (!username || !email || !password) {
            console.log('Error: Username, email, and password are required');
            return res.status(400).json({
                success: false,
                message: 'Username, email, and password are required'
            });
        }
        
        console.log('Validating email format...');
        if (!email.endsWith('@kitsw.ac.in')) {
            console.log(`Error: Invalid email format: ${email}. Must end with @kitsw.ac.in`);
            return res.status(400).json({
                success: false,
                message: 'Please use a valid @kitsw.ac.in email address'
            });
        }
        
        console.log('Hashing password...');
        const passwordHash = await bcrypt.hash(password, 10);
        
        console.log('Attempting to create user:', { username, email });
        
        try {
            const result = await db.query(
                'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
                [username, email, passwordHash]
            );
            
            console.log('User created successfully:', result.rows[0]);
            
            res.status(201).json({
                success: true,
                user: {
                    id: result.rows[0].id,
                    username: result.rows[0].username,
                    email: result.rows[0].email
                }
            });
            
        } catch (dbError) {
            console.error('Database error during signup:', dbError);
            
            // Check for duplicate email or username error
            if (dbError.code === '23505') { // Unique violation
                const detail = dbError.detail || '';
                if (detail.includes('email')) {
                    return res.status(400).json({
                        success: false,
                        message: 'This email is already registered'
                    });
                } else if (detail.includes('username')) {
                    return res.status(400).json({
                        success: false,
                        message: 'This username is already taken'
                    });
                } else {
                    return res.status(400).json({
                        success: false,
                        message: 'User already exists'
                    });
                }
            }
            
            throw dbError; // Re-throw to be caught by the outer catch
        }
        
    } catch (error) {
        console.error('Unexpected error in signup:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred during signup',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// User login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            console.log('Login attempt missing username or password');
            return res.status(400).json({ 
                success: false, 
                message: 'Username and password are required' 
            });
        }
        
        console.log(`Login attempt for user: ${username}`);
        
        // Find user
        const result = await db.query(
            'SELECT id, username, password_hash, email FROM users WHERE username = $1',
            [username]
        );
        
        if (result.rows.length === 0) {
            console.log(`User not found: ${username}`);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }
        
        const user = result.rows[0];
        console.log(`User found: ${user.username} (ID: ${user.id})`);
        
        // Verify password
        console.log('Verifying password...');
        const validPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!validPassword) {
            console.log('Invalid password for user:', username);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }
        
        // Generate JWT
        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        
        // Get user data (including email)
        const userData = {
            id: user.id,
            username: user.username,
            email: user.email
        };
        
        res.json({
            success: true,
            token,
            user: userData
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Error during login',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Upload a new snap
app.post('/api/snaps', authenticateToken, upload.single('image'), async (req, res) => {
    console.log('=== NEW UPLOAD REQUEST ===');
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
    console.log('File info:', req.file ? {
        originalname: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        path: req.file.path
    } : 'No file uploaded');
    console.log('Request body:', req.body);
    console.log('User from auth middleware:', req.user);

    if (!req.file) {
        console.error('No file was uploaded');
        return res.status(400).json({ success: false, message: 'No image file provided' });
    }

    const { caption = '', hashtags = '', location = '' } = req.body;
    console.log('Processing upload with data:', { caption, hashtags, location });
    
    let client;
    try {
        client = await db.getClient();
        console.log('Connected to database');
        
        await client.query('BEGIN');
        console.log('Transaction started');
        
        // Use user from authenticateToken middleware
        const userId = req.user.id;
        const username = req.user.username;
        console.log('User from middleware:', { userId, username });
        
        // Read the image file
        console.log('Reading image file from:', req.file.path);
        let imageData;
        try {
            imageData = fs.readFileSync(req.file.path);
            console.log('Successfully read image file, size:', imageData.length, 'bytes');
        } catch (fileError) {
            console.error('Error reading image file:', fileError);
            throw new Error('Failed to read the uploaded file');
        }
        
        const mimeType = req.file.mimetype;
        const imageUrl = `/api/snaps/image/${Date.now()}-${req.file.originalname}`;
        
        console.log('Preparing to insert snap into database...');
        console.log('Data to insert:', {
            userId,
            caption,
            location,
            imageDataLength: imageData.length,
            mimeType,
            imageUrl
        });
        
        // Calculate expiration time (24 hours from now)
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        console.log('Snap will expire at:', expiresAt.toISOString());
        
        // Insert the snap with image data and expiration
        const queryText = `
            INSERT INTO snaps (
                user_id, 
                caption, 
                location, 
                image_data, 
                mime_type,
                image_url,
                expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, created_at, expires_at
        `;
        
        console.log('Executing database query...');
        const result = await client.query(queryText, [
            userId, 
            caption, 
            location, 
            imageData, 
            mimeType,
            imageUrl,
            expiresAt
        ]);
        
        console.log('Database insert successful, new snap ID:', result.rows[0]?.id);
        const snapId = result.rows[0].id;
        
        // Process and insert hashtags into separate table
        if (hashtags && hashtags.trim()) {
            console.log('Processing hashtags:', hashtags);
            // Extract hashtags (split by spaces, commas, or # symbols)
            const hashtagArray = hashtags
                .split(/[\s,#]+/)
                .filter(tag => tag.trim().length > 0)
                .map(tag => tag.replace(/^#/, '').toLowerCase());
            
            console.log('Extracted hashtags:', hashtagArray);
            
            // Insert each hashtag
            for (const hashtag of hashtagArray) {
                await client.query(
                    'INSERT INTO hashtags (snap_id, hashtag) VALUES ($1, $2)',
                    [snapId, hashtag]
                );
            }
            console.log(`Inserted ${hashtagArray.length} hashtags for snap ${snapId}`);
        }
        
        // Remove the temporary file
        try {
            fs.unlinkSync(req.file.path);
            console.log('Temporary file cleaned up');
        } catch (cleanupError) {
            console.warn('Could not clean up temporary file:', cleanupError.message);
        }
        
        const snap = {
            id: snapId,
            username: username,
            imageUrl: `/api/snaps/image/${snapId}`,
            caption: caption,
            hashtags: hashtags,
            location: location,
            createdAt: result.rows[0].created_at
        };
        
        await client.query('COMMIT');
        console.log('Transaction committed');
        
        // Notify connected clients about the new snap
        if (emitNewSnap) {
            emitNewSnap(snap);
            console.log('New snap event emitted');
        }
        
        console.log('Upload successful, sending response');
        res.status(201).json({
            success: true,
            snap: snap
        });
        
    } catch (error) {
        console.error('=== UPLOAD ERROR ===');
        console.error('Error name:', error.name);
        console.error('Error message:', error.message);
        console.error('Error stack:', error.stack);
        
        // Clean up the uploaded file if something went wrong
        if (req.file && req.file.path) {
            try { 
                fs.unlinkSync(req.file.path); 
                console.log('Cleaned up file after error');
            } catch (e) {
                console.warn('Could not clean up file after error:', e.message);
            }
        }
        
        if (client) {
            try {
                await client.query('ROLLBACK');
                console.log('Transaction rolled back');
            } catch (rollbackError) {
                console.error('Error during rollback:', rollbackError.message);
            }
        }
        
        res.status(500).json({ 
            success: false, 
            message: 'Failed to upload snap',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        if (client) {
            client.release();
            console.log('Database client released');
        }
        console.log('=== UPLOAD REQUEST COMPLETED ===');
    }
});

// Serve image data from database
app.get('/api/snaps/image/:id', async (req, res) => {
    try {
        const result = await db.query(
            'SELECT image_data, mime_type FROM snaps WHERE id = $1',
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).send('Image not found');
        }

        const { image_data, mime_type } = result.rows[0];
        
        // Set appropriate headers
        res.set('Content-Type', mime_type);
        res.set('Cache-Control', 'public, max-age=31536000'); // Cache for 1 year
        res.send(image_data);
        
    } catch (error) {
        console.error('Error serving image:', error);
        res.status(500).send('Error serving image');
    }
});

// Get paginated feed of snaps
app.get('/api/feed', async (req, res) => {
    try {
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 10));
        const offset = (page - 1) * limit;
        
        // Get snaps with user info
        const result = await db.query(
            `SELECT 
                s.id, 
                '/api/snaps/image/' || s.id as "imageUrl",
                s.caption,
                s.location,
                s.created_at as "createdAt",
                u.username,
                u.profile_picture_url as "profilePictureUrl"
            FROM snaps s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.created_at DESC
            LIMIT $1 OFFSET $2`,
            [limit, offset]
        );
        
        // Get hashtags for each snap
        for (let snap of result.rows) {
            const hashtagResult = await db.query(
                'SELECT hashtag FROM hashtags WHERE snap_id = $1 ORDER BY created_at',
                [snap.id]
            );
            snap.hashtags = hashtagResult.rows.map(row => row.hashtag);
        }
        
        // Get total count for pagination
        const countResult = await db.query('SELECT COUNT(*) FROM snaps');
        const totalSnaps = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(totalSnaps / limit);
        
        res.json({
            success: true,
            snaps: result.rows,
            pagination: {
                page,
                limit,
                totalItems: totalSnaps,
                totalPages
            }
        });
        
    } catch (error) {
        console.error('Error fetching feed:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch feed',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Get a single snap by ID
app.get('/api/snaps/:id', async (req, res) => {
    try {
        const result = await db.query(
            `SELECT 
                s.id, 
                s.image_url as "imageUrl",
                s.caption,
                s.location,
                s.created_at as "createdAt",
                u.username,
                u.profile_picture_url as "profilePictureUrl"
            FROM snaps s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = $1`,
            [req.params.id]
        );
        
        if (result.rows.length > 0) {
            // Get hashtags for this snap from hashtags table
            const hashtagResult = await db.query(
                'SELECT hashtag FROM hashtags WHERE snap_id = $1 ORDER BY created_at',
                [req.params.id]
            );
            
            // Add hashtags array to the snap data
            result.rows[0].hashtags = hashtagResult.rows.map(row => row.hashtag);
        }
        
        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Snap not found'
            });
        }
        
        res.json({
            success: true,
            snap: result.rows[0]
        });
        
    } catch (error) {
        console.error('Error fetching snap:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch snap'
        });
    }
});

// Admin authentication endpoint
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        // Get admin user from database
        const result = await db.query(
            'SELECT id, username, password_hash, is_active FROM admin_users WHERE username = $1',
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Login failed'
            });
        }

        const admin = result.rows[0];
        
        if (!admin.is_active) {
            return res.status(401).json({
                success: false,
                message: 'Login failed'
            });
        }

        // Verify password
        const bcrypt = require('bcrypt');
        const passwordMatch = await bcrypt.compare(password, admin.password_hash);

        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: 'Login failed'
            });
        }

        // Update last login time
        await db.query(
            'UPDATE admin_users SET last_login = NOW() WHERE id = $1',
            [admin.id]
        );

        // Generate JWT token for admin session
        const adminToken = jwt.sign(
            { 
                id: admin.id, 
                username: admin.username, 
                role: 'admin' 
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            message: 'Login successful',
            token: adminToken,
            admin: {
                id: admin.id,
                username: admin.username
            }
        });

    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed'
        });
    }
});

// Delete a snap by ID (Admin functionality)
app.delete('/api/snaps/:id', async (req, res) => {
    const client = await db.getClient();
    try {
        await client.query('BEGIN');
        
        // Delete hashtags first (due to foreign key constraint)
        await client.query('DELETE FROM hashtags WHERE snap_id = $1', [req.params.id]);
        
        // Delete the snap
        const result = await client.query('DELETE FROM snaps WHERE id = $1', [req.params.id]);
        
        if (result.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                success: false,
                message: 'Snap not found'
            });
        }
        
        await client.query('COMMIT');
        console.log(`Snap ${req.params.id} deleted successfully`);
        
        res.json({
            success: true,
            message: 'Snap deleted successfully'
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error deleting snap:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete snap'
        });
    } finally {
        client.release();
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({
        success: false,
        message: 'An unexpected error occurred',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// Cleanup expired snaps function
async function cleanupExpiredSnaps() {
    console.log('Running expired snaps cleanup...');
    let client;
    try {
        client = await db.getClient();
        const result = await client.query(
            'DELETE FROM snaps WHERE expires_at < NOW() RETURNING id'
        );
        
        if (result.rows.length > 0) {
            console.log(`Deleted ${result.rows.length} expired snaps:`, result.rows.map(r => r.id));
        } else {
            console.log('No expired snaps found to delete');
        }
    } catch (error) {
        console.error('Error during expired snaps cleanup:', error);
    } finally {
        if (client) client.release();
    }
}

// Initialize database and start server
db.initDb().then(() => {
    // Start cleanup job - runs every hour
    setInterval(cleanupExpiredSnaps, 60 * 60 * 1000); // 1 hour
    console.log('Expired snaps cleanup job scheduled (runs every hour)');
    
    // Run cleanup immediately on startup
    cleanupExpiredSnaps();
    
    server.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log('Snaps will automatically expire after 24 hours');
    });
}).catch(error => {
    console.error('Failed to initialize database:', error);
    process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
});

module.exports = { app };
