// check-schema.js
const { Pool } = require('pg');
require('dotenv').config();

async function checkSchema() {
    const pool = new Pool({
        user: process.env.PG_USER,
        host: process.env.PG_HOST,
        database: process.env.PG_DATABASE,
        password: process.env.PG_PASSWORD,
        port: process.env.PG_PORT || 5432,
    });

    const client = await pool.connect();

    try {
        console.log('Checking database schema...');
        
        // Check if users table exists and show its structure
        const result = await client.query(`
            SELECT column_name, data_type, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_name = 'users'
            ORDER BY ordinal_position;
        `);

        console.log('\nUsers table structure:');
        console.table(result.rows);

        // Check for any constraints on the email column
        const constraints = await client.query(`
            SELECT conname, convalidated, conkey, confkey, confdeltype
            FROM pg_constraint
            WHERE conrelid = 'users'::regclass;
        `);

        if (constraints.rows.length > 0) {
            console.log('\nTable constraints:');
            console.table(constraints.rows);
        }

    } catch (error) {
        console.error('Error checking schema:', error);
    } finally {
        client.release();
        await pool.end();
    }
}

checkSchema().catch(console.error);
