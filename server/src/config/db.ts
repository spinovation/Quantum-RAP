import { Pool } from 'pg';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

dotenv.config();

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_DATABASE || 'quarkshield',
  password: process.env.DB_PASSWORD || 'postgres',
  port: Number(process.env.DB_PORT) || 5432,
});

export const initDb = async () => {
  try {
    const client = await pool.connect();
    console.log('Connected to PostgreSQL successfully.');
    
    // Read and run schema.sql to initialize tables
    const schemaPath = path.join(__dirname, '../models/schema.sql');
    if (fs.existsSync(schemaPath)) {
      const schemaSql = fs.readFileSync(schemaPath, 'utf8');
      await client.query(schemaSql);
      console.log('Database tables verified/created successfully.');
    } else {
      console.warn('Warning: schema.sql file not found at', schemaPath);
    }
    
    client.release();
  } catch (err) {
    console.error('Database connection error:', err);
    process.exit(1);
  }
};

export default pool;
