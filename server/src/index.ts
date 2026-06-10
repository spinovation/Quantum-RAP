import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import router from './routes/routes';
import { initDb } from './config/db';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api', router);

// Serve static frontend assets in production
if (process.env.NODE_ENV === 'production') {
  const distPath = path.join(__dirname, '../../dist');
  
  // Serve static assets (JS/CSS have file hashes and can be safely cached)
  app.use(express.static(distPath, {
    setHeaders: (res, filePath) => {
      if (path.basename(filePath) === 'index.html') {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      }
    }
  }));
  
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) {
      return next();
    }
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.sendFile(path.join(distPath, 'index.html'));
  });
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date() });
});

// Start server
const startServer = async () => {
  // 1. Initialize PostgreSQL tables
  await initDb();
  
  // 2. Listen for requests
  app.listen(PORT, () => {
    console.log(`QuarkShield Server running on port ${PORT}`);
  });
};

startServer();
