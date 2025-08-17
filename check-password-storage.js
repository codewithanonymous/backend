// check-password-storage.js
const { Pool } = require('pg');
require('dotenv').config();

async function checkPasswordStorage() {
    const pool = new Pool({
        user: process.env.PG_USER,
        host: process.env.PG_HOST,
        database: process.env.PG_DATABASE,
        password: process.env.PG_PASSWORD,
        port: process.env.PG_PORT || 5432,
    });

    const client = await pool.connect();

    try {
        console.log('Checking password storage in users table...');
        
        // Check table structure
        const tableInfo = await client.query(`
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'users'
            AND column_name IN ('password', 'password_hash')
        `);
        
        console.log('\nPassword-related columns:');
        console.table(tableInfo.rows);

        // Check sample data (first 5 users)
        const sampleUsers = await client.query(`
            SELECT id, email, 
                   password_hash, 
                   length(password_hash) as password_length,
                   CASE 
                       WHEN password_hash ~ '^[0-9a-f]{64}$' THEN 'Hashed (SHA-256)'
                       WHEN password_hash ~ '^\$2[aby]\$' THEN 'Bcrypt hashed'
                       ELSE 'Plain text or other format'
                   END as password_type
            FROM users
            LIMIT 5
        `);
        
        console.log('\nSample user data:');
        console.table(sampleUsers.rows);

    } catch (error) {
        console.error('Error checking password storage:', error);
    } finally {
        client.release();
        await pool.end();
    }
}

checkPasswordStorage().catch(console.error);
