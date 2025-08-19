const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const INTERNAL_DB_URL = process.env.DATABASE_URL;


// Replace this with your internal DB URL from Render

// PostgreSQL connection pool
const pool = new Pool({
    connectionString: INTERNAL_DB_URL,
    ssl: {
        rejectUnauthorized: false // Required for Render
    }
});

// Test connection
pool.query('SELECT NOW()', (err) => {
    if (err) {
        console.error('❌ Error connecting to PostgreSQL:', err);
    } else {
        console.log('✅ Connected to PostgreSQL database');
    }
});

// Initialize database tables
const initDb = async () => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        await client.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                last_login TIMESTAMPTZ,
                profile_picture_url VARCHAR(512),
                bio TEXT,
                is_active BOOLEAN DEFAULT true
            );
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS snaps (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                image_url VARCHAR(512) NOT NULL,
                caption TEXT,
                location VARCHAR(255),
                created_at TIMESTAMPTZ DEFAULT NOW(),
                expires_at TIMESTAMPTZ,
                view_count INTEGER DEFAULT 0,
                is_public BOOLEAN DEFAULT true,
                image_data BYTEA,
                mime_type VARCHAR(50)
            );
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS hashtags (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                snap_id UUID REFERENCES snaps(id) ON DELETE CASCADE,
                hashtag VARCHAR(100) NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);

        await client.query('CREATE INDEX IF NOT EXISTS idx_hashtags_snap_id ON hashtags(snap_id)');
        await client.query('CREATE INDEX IF NOT EXISTS idx_hashtags_hashtag ON hashtags(hashtag)');

        await client.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                last_login TIMESTAMPTZ,
                is_active BOOLEAN DEFAULT true
            );
        `);

        // Create default or update admin user
        const adminCheck = await client.query('SELECT COUNT(*) FROM admin_users');
        const adminPassword = 'amixuser@123';
        const passwordHash = await bcrypt.hash(adminPassword, 10);

        if (parseInt(adminCheck.rows[0].count) === 0) {
            await client.query(
                'INSERT INTO admin_users (username, password_hash) VALUES ($1, $2)',
                ['amixuser@123', passwordHash]
            );
            console.log('✅ Default admin user created: amixuser@123 / amixuser@123');
        } else {
            await client.query(
                'UPDATE admin_users SET username = $1, password_hash = $2',
                ['amixuser@123', passwordHash]
            );
            console.log('✅ Admin credentials updated');
        }

        await client.query('COMMIT');
        console.log('✅ Database tables initialized');
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('❌ Error initializing database:', err);
    } finally {
        client.release();
    }
};

// Auto-init on load
initDb().catch(console.error);

// Export
module.exports = {
    query: (text, params) => pool.query(text, params),
    getClient: () => pool.connect(),
    pool,
    initDb,
};

