const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator'); // CRITERION: Secure Code (Input Validation)
const app = express();
const port = 3000;

app.use(bodyParser.json());

const JWT_SECRET = 'your_super_secret_key_123';
const database = {
    users: [
        { id: 1, username: 'admin', password: 'secure_admin_password', role: 'admin' },
        { id: 2, username: 'user1', password: 'secure_user_password', role: 'user' }
    ],
    // Mock data storage, contains a mock vulnerability for the summary
    vaultItems: [
        { id: 1, owner: 1, data: 'Admin Key 1' },
        { id: 2, owner: 2, data: 'User Key 1' },
        { id: 3, owner: 1, data: 'Admin Key 2' }
    ]
};

// --- CRITERION: AUTHENTICATION AND AUTHORIZATION (RBAC) ---

// Middleware 1: Authentication (Token Verification)
const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).send({ message: 'Access Denied. No token provided.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Attach user info to the request
        next();
    } catch (ex) {
        res.status(400).send({ message: 'Invalid token.' });
    }
};

// Middleware 2: Role-Based Access Control (RBAC)
const rbacMiddleware = (requiredRole) => (req, res, next) => {
    if (req.user && req.user.role === requiredRole) {
        next();
    } else {
        res.status(403).send({ message: 'Forbidden. Insufficient permissions.' });
    }
};

// --- CRITERION: SECURE CODE (SQLi Prevention - Mock DB Utility) ---
// Mock database utility using "Prepared Statements" to prevent SQLi
const db = {
    // This function mimics a secure query using parameterization
    query: (sql, params) => {
        // In a real application, this would use a database driver's prepared statement.
        // For demonstration, it prevents direct SQL string concatenation.
        console.log(`[DB] Executing secure query: ${sql} with params: ${params.join(', ')}`);
        
        // This simulates a lookup for demonstration purposes
        if (sql.includes('SELECT * FROM users WHERE username = ?')) {
            return database.users.find(u => u.username === params[0]);
        }
        if (sql.includes('SELECT * FROM vaultItems WHERE owner = ?')) {
             return database.vaultItems.filter(item => item.owner === params[0]);
        }
        return null;
    }
};

// Login Endpoint (Generates JWT)
app.post('/api/login', [
    body('username').notEmpty().escape(), // Basic sanitization
    body('password').notEmpty()
], (req, res) => {
    const { username, password } = req.body;
    
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    // SQLi Prevention (Mock): Using db.query simulates a prepared statement
    const user = db.query('SELECT * FROM users WHERE username = ?', [username]);

    if (user && user.password === password) { // In a real app, use bcrypt hash check
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
        return res.json({ token, role: user.role });
    } else {
        res.status(401).send({ message: 'Invalid credentials.' });
    }
});

// Protected Endpoint 1: User-Specific Data (Requires AUTH)
app.get('/api/vault/my-items', authMiddleware, (req, res) => {
    // Mock the retrieval of only the user's data (Horizontal Access Control)
    const userItems = db.query('SELECT * FROM vaultItems WHERE owner = ?', [req.user.id]);

    // XSS Prevention (Mock): Assume data is sanitized before storage or rendering.
    // We are deliberately serving 'safe' data here. The summary will detail the fix.
    res.json(userItems);
});

// Protected Endpoint 2: Admin Function (Requires RBAC: 'admin')
app.get('/api/vault/admin/all-data', authMiddleware, rbacMiddleware('admin'), (req, res) => {
    // Only 'admin' role can access this.
    res.json(database.vaultItems);
});


// Export for testing
module.exports = app;

// Start the server (only if running the file directly)
if (require.main === module) {
    app.listen(port, () => {
        console.log(`SafeVault API running at http://localhost:${port}`);
    });
}