// db-pg.js - PostgreSQL database interactions
const { Pool } = require('pg');
require('dotenv').config();

// Database connection configuration
const pool = new Pool({
    user: process.env.PG_USER || 'postgres',
    host: process.env.PG_HOST || 'localhost',
    database: process.env.PG_DATABASE || 'snapchat_style_app',
    password: process.env.PG_PASSWORD || 'amixuser@123',
    port: process.env.PG_PORT || 5432,
});

// Test the connection
pool.query('SELECT NOW()', (err) => {
    if (err) {
        console.error('Error connecting to PostgreSQL:', err);
    } else {
        console.log('Connected to PostgreSQL database');
    }
});

// Initialize database tables
const initDb = async () => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // Enable UUID extension
        await client.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
        
        // Create users table
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_login TIMESTAMPTZ,
                profile_picture_url VARCHAR(512),
                bio TEXT,
                is_active BOOLEAN DEFAULT true
            )
        `);

        // Create snaps table
        await client.query(`
            CREATE TABLE IF NOT EXISTS snaps (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                image_url VARCHAR(512) NOT NULL,
                caption TEXT,
                location VARCHAR(255),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ,
                view_count INTEGER DEFAULT 0,
                is_public BOOLEAN DEFAULT true,
                image_data BYTEA,
                mime_type VARCHAR(50)
            )
        `);

        // Create hashtags table
        await client.query(`
            CREATE TABLE IF NOT EXISTS hashtags (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                snap_id UUID NOT NULL REFERENCES snaps(id) ON DELETE CASCADE,
                hashtag VARCHAR(100) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        `);

        // Create index for hashtag lookups
        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_hashtags_snap_id ON hashtags(snap_id)
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_hashtags_hashtag ON hashtags(hashtag)
        `);

        // Create admin_users table
        await client.query(`
            CREATE TABLE IF NOT EXISTS admin_users (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_login TIMESTAMPTZ,
                is_active BOOLEAN DEFAULT true
            )
        `);

        // Add missing columns to existing snaps table if they don't exist
        await client.query(`
            DO $$
            BEGIN
                -- Add image_data column if it doesn't exist
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='snaps' AND column_name='image_data') THEN
                    ALTER TABLE snaps ADD COLUMN image_data BYTEA;
                    RAISE NOTICE 'Added image_data column to snaps table';
                END IF;
                
                -- Add mime_type column if it doesn't exist
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                              WHERE table_name='snaps' AND column_name='mime_type') THEN
                    ALTER TABLE snaps ADD COLUMN mime_type VARCHAR(50);
                    RAISE NOTICE 'Added mime_type column to snaps table';
                END IF;
            END $$;
        `);

        // Insert default admin user if none exists
        const adminCheck = await client.query('SELECT COUNT(*) FROM admin_users');
        if (parseInt(adminCheck.rows[0].count) === 0) {
            const bcrypt = require('bcrypt');
            const defaultPassword = 'amixuser@123';
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(defaultPassword, saltRounds);
            
            await client.query(
                'INSERT INTO admin_users (username, password_hash) VALUES ($1, $2)',
                ['amixuser@123', hashedPassword]
            );
            console.log('Default admin user created: amixuser@123/amixuser@123');
        } else {
            // Update existing admin credentials
            const bcrypt = require('bcrypt');
            const newPassword = 'amixuser@123';
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
            
            await client.query(
                'UPDATE admin_users SET username = $1, password_hash = $2',
                ['amixuser@123', hashedPassword]
            );
            console.log('Admin credentials updated to: amixuser@123/amixuser@123');
        }
        
        await client.query('COMMIT');
        console.log('Database tables initialized');
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error initializing database:', error);
        throw error;
    } finally {
        client.release();
    }
};

// Initialize the database when this module is loaded
initDb().catch(console.error);

// Export the pool and initDb function to be used in other modules
module.exports = {
    query: (text, params) => pool.query(text, params),
    getClient: () => pool.connect(),
    pool,
    initDb,
};
