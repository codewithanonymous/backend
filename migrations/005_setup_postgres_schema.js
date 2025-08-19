// migrations/005_setup_postgres_schema.js
const { Pool } = require('pg');
require('dotenv').config();

async function runMigration() {
    const pool = new Pool({
        user: process.env.PG_USER || 'postgres',
        host: process.env.PG_HOST || 'localhost',
        database: process.env.PG_DATABASE || 'postgres', // Connect to default database first
        password: process.env.PG_PASSWORD || 'amixuser@123',
        port: process.env.PG_PORT || 5432,
    });

    const client = await pool.connect();

    try {
        await client.query('BEGIN');
        
        // Create database if it doesn't exist
        await client.query(`
            CREATE DATABASE ${process.env.PG_DATABASE || 'snapchat_style_app'}
            WITH OWNER = postgres
            ENCODING = 'UTF8'
            LC_COLLATE = 'English_United States.1252'
            LC_CTYPE = 'English_United States.1252'
            TABLESPACE = pg_default
            CONNECTION LIMIT = -1;
        `).catch(err => {
            if (err.code !== '42P04') throw err; // Ignore error if database already exists
            console.log('Database already exists, continuing...');
        });

        // Connect to our database
        await client.end();
        pool.end();

        const appPool = new Pool({
            user: process.env.PG_USER || 'postgres',
            host: process.env.PG_HOST || 'localhost',
            database: process.env.PG_DATABASE || 'snapchat_style_app',
            password: process.env.PG_PASSWORD || 'amixuser@123',
            port: process.env.PG_PORT || 5432,
        });

        const appClient = await appPool.connect();

        try {
            await appClient.query('BEGIN');
            
            // Enable UUID extension
            await appClient.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

            // Create users table
            await appClient.query(`
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    profile_picture_url VARCHAR(512),
                    bio TEXT,
                    is_active BOOLEAN DEFAULT true
                )
            `);

            // Create snaps table
            await appClient.query(`
                CREATE TABLE IF NOT EXISTS snaps (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    image_url VARCHAR(512) NOT NULL,
                    image_data BYTEA,
                    mime_type VARCHAR(100),
                    caption TEXT,
                    hashtags TEXT,
                    location VARCHAR(255),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at TIMESTAMPTZ,
                    view_count INTEGER DEFAULT 0,
                    is_public BOOLEAN DEFAULT true
                )
            `);

            // Create views table to track viewed snaps
            await appClient.query(`
                CREATE TABLE IF NOT EXISTS views (
                    snap_id UUID REFERENCES snaps(id) ON DELETE CASCADE,
                    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                    viewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (snap_id, user_id)
                )
            `);

            // Create indexes
            await appClient.query('CREATE INDEX IF NOT EXISTS idx_snaps_user_id ON snaps(user_id)');
            await appClient.query('CREATE INDEX IF NOT EXISTS idx_snaps_created_at ON snaps(created_at)');
            await appClient.query('CREATE INDEX IF NOT EXISTS idx_views_snap_id ON views(snap_id)');
            await appClient.query('CREATE INDEX IF NOT EXISTS idx_views_user_id ON views(user_id)');

            await appClient.query('COMMIT');
            console.log('Database schema created successfully');
            
        } catch (error) {
            await appClient.query('ROLLBACK');
            console.error('Error creating database schema:', error);
            throw error;
        } finally {
            appClient.release();
            await appPool.end();
        }
        
    } catch (error) {
        console.error('Migration failed:', error);
        process.exit(1);
    } finally {
        client.release();
        await pool.end();
    }
}

runMigration().catch(console.error);
