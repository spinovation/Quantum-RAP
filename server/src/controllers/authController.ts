import { Request, Response } from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import pool from '../config/db';
import { sendVerificationEmail } from '../utils/mailer';

const ITERATIONS = 10000;
const KEY_LEN = 64;
const DIGEST = 'sha512';

// Helper to hash password using Node pbkdf2Sync
function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LEN, DIGEST).toString('hex');
}

// POST /api/auth/register
export const register = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Missing email or password.' });
    }

    const trimmedEmail = email.trim().toLowerCase();

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(trimmedEmail)) {
      return res.status(400).json({ error: 'Please provide a valid email address.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    }

    // Check if user exists (email)
    const checkUser = await pool.query(
      'SELECT id, email FROM users WHERE email = $1',
      [trimmedEmail]
    );
    if (checkUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email is already registered.' });
    }

    // Check if this is the first user. If so, they are Admin
    const userCount = await pool.query('SELECT COUNT(*) FROM users');
    const role = Number(userCount.rows[0].count) === 0 ? 'admin' : 'user';

    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(password, salt);
    const verificationToken = crypto.randomBytes(32).toString('hex');

    const insertRes = await pool.query(
      'INSERT INTO users (email, password_hash, salt, role, email_verified, verification_token) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, role',
      [trimmedEmail, hash, salt, role, false, verificationToken]
    );

    // Send verification email
    try {
      const host = req.get('x-forwarded-host') || req.get('host') || 'localhost:5000';
      const protocol = req.get('x-forwarded-proto') || req.protocol || 'http';
      const origin = `${protocol}://${host}`;
      const displayUsername = trimmedEmail.split('@')[0];
      await sendVerificationEmail(trimmedEmail, displayUsername, verificationToken, origin);
    } catch (mailErr) {
      console.error('Failed to send verification email:', mailErr);
      return res.status(500).json({ error: 'Registration succeeded, but failed to send verification email. Please check SMTP server logs.' });
    }

    res.status(201).json({
      success: true,
      message: 'Registration successful! A verification link has been sent to your email address. Please verify it before logging in.',
      user: {
        id: insertRes.rows[0].id,
        email: insertRes.rows[0].email,
        role: insertRes.rows[0].role,
      }
    });
  } catch (err: any) {
    console.error('Registration error:', err);
    res.status(500).json({ error: `Registration failed: ${err.message}` });
  }
};

// POST /api/auth/login
export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Missing email or password.' });
    }

    const trimmedEmail = email.trim().toLowerCase();
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [trimmedEmail]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    const user = result.rows[0];

    // Check email verification status
    if (!user.email_verified) {
      return res.status(400).json({ error: 'Email verification pending. Please verify your email address to log in.' });
    }

    const candidateHash = hashPassword(password, user.salt);

    // Verify hash match using timingSafeEqual to avoid timing side-channel attacks
    const actualBuffer = Buffer.from(user.password_hash, 'hex');
    const candidateBuffer = Buffer.from(candidateHash, 'hex');
    if (actualBuffer.length !== candidateBuffer.length || !crypto.timingSafeEqual(actualBuffer, candidateBuffer)) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }

    // Generate session token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // Expires in 7 days

    await pool.query(
      'INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, $3)',
      [token, user.id, expiresAt]
    );

    const isAdminNode = process.env.IS_ADMIN_NODE === 'true';
    let tenantPort: number | null = null;
    if (isAdminNode && user.role !== 'admin') {
      tenantPort = getTenantPort(user.email);
    }

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isAdminNode,
        tenantPort,
      }
    });
  } catch (err: any) {
    console.error('Login error:', err);
    res.status(500).json({ error: `Login failed: ${err.message}` });
  }
};

// GET /api/auth/verify
export const verify = async (req: Request, res: Response) => {
  try {
    const token = req.query.token;
    if (!token || typeof token !== 'string') {
      return res.status(400).send(renderVerifyResult(false, 'Missing or invalid verification token.'));
    }

    // Find user by token
    const result = await pool.query('SELECT * FROM users WHERE verification_token = $1', [token]);
    if (result.rows.length === 0) {
      return res.status(400).send(renderVerifyResult(false, 'The verification link is invalid or has expired.'));
    }

    const user = result.rows[0];

    // Mark as verified
    await pool.query(
      'UPDATE users SET email_verified = true, verification_token = NULL WHERE id = $1',
      [user.id]
    );

    res.send(renderVerifyResult(true));
  } catch (err: any) {
    console.error('Verification error:', err);
    res.status(500).send(renderVerifyResult(false, `Verification error: ${err.message}`));
  }
};

// Helper to render HTML result
function renderVerifyResult(success: boolean, message?: string): string {
  const primaryColor = '#3b82f6';
  const secondaryColor = '#8b5cf6';
  const successColor = '#10b981';
  const errorColor = '#ef4444';
  
  const icon = success ? '✓' : '✗';
  const iconColor = success ? successColor : errorColor;
  const iconBg = success ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)';
  const iconBorder = success ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)';
  const title = success ? 'Identity Verified' : 'Verification Failed';
  const description = success 
    ? 'Your cryptographic access credentials have been authenticated. You may now securely log in to the QuarkShield console.'
    : (message || 'An error occurred during verification.');
  
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${title} | QuarkShield</title>
      <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
      <style>
        :root {
          --bg: #030712;
          --card-bg: rgba(17, 24, 39, 0.7);
          --border: rgba(59, 130, 246, 0.2);
          --primary: ${primaryColor};
          --secondary: ${secondaryColor};
          --text: #f3f4f6;
          --text-muted: #9ca3af;
        }
        
        * {
          box-sizing: border-box;
          margin: 0;
          padding: 0;
        }

        body {
          font-family: 'Outfit', sans-serif;
          background-color: var(--bg);
          color: var(--text);
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          overflow: hidden;
          position: relative;
        }

        body::before {
          content: '';
          position: absolute;
          top: -10%;
          left: -10%;
          width: 50%;
          height: 50%;
          background: radial-gradient(circle, rgba(59, 130, 246, 0.15) 0%, transparent 70%);
          filter: blur(50px);
          pointer-events: none;
        }

        body::after {
          content: '';
          position: absolute;
          bottom: -10%;
          right: -10%;
          width: 50%;
          height: 50%;
          background: radial-gradient(circle, rgba(139, 92, 246, 0.15) 0%, transparent 70%);
          filter: blur(50px);
          pointer-events: none;
        }

        .container {
          background: var(--card-bg);
          backdrop-filter: blur(16px);
          -webkit-backdrop-filter: blur(16px);
          border: 1px solid var(--border);
          border-radius: 20px;
          padding: 48px;
          max-width: 480px;
          width: 90%;
          text-align: center;
          box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 10px 10px -5px rgba(0, 0, 0, 0.5),
                      0 0 40px rgba(59, 130, 246, 0.1);
          z-index: 10;
          animation: fadeIn 0.8s ease-out;
        }

        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }

        .logo {
          font-size: 32px;
          font-weight: 800;
          letter-spacing: 0.1em;
          background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          margin-bottom: 32px;
        }

        .icon-container {
          width: 80px;
          height: 80px;
          margin: 0 auto 24px;
          display: flex;
          align-items: center;
          justify-content: center;
          border-radius: 50%;
          background: ${iconBg};
          border: 1px solid ${iconBorder};
          position: relative;
        }

        .icon-container::after {
          content: '';
          position: absolute;
          width: 100%;
          height: 100%;
          border-radius: 50%;
          border: 1px solid ${iconBorder};
          animation: pulse 2s infinite;
        }

        @keyframes pulse {
          0% { transform: scale(1); opacity: 0.8; }
          100% { transform: scale(1.4); opacity: 0; }
        }

        .icon {
          font-size: 40px;
          line-height: 1;
          color: ${iconColor};
        }

        h1 {
          font-size: 24px;
          font-weight: 600;
          color: #ffffff;
          margin-bottom: 12px;
        }

        p {
          color: var(--text-muted);
          font-size: 15px;
          line-height: 1.6;
          margin-bottom: 32px;
        }

        .btn {
          display: inline-block;
          width: 100%;
          background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
          color: #ffffff;
          text-decoration: none;
          font-weight: 600;
          font-size: 15px;
          padding: 14px 28px;
          border-radius: 8px;
          box-shadow: 0 4px 14px rgba(59, 130, 246, 0.4);
          transition: all 0.3s ease;
          border: none;
          cursor: pointer;
        }

        .btn:hover {
          transform: translateY(-2px);
          box-shadow: 0 6px 20px rgba(59, 130, 246, 0.6);
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="logo">QUARKSHIELD</div>
        
        <div class="icon-container">
          <span class="icon">${icon}</span>
        </div>
        
        <h1>${title}</h1>
        <p>${description}</p>
        
        <a href="/" class="btn">${success ? 'Proceed to Login' : 'Back to Login'}</a>
      </div>
    </body>
    </html>
  `;
}

// POST /api/auth/logout
export const logout = async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing session token.' });
    }

    const token = authHeader.split(' ')[1];
    await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
    res.json({ success: true, message: 'Logged out successfully.' });
  } catch (err: any) {
    console.error('Logout error:', err);
    res.status(500).json({ error: `Logout failed: ${err.message}` });
  }
};

// Helper: Get tenant port from docker-compose.yml on the host
export function getTenantPort(email: string): number | null {
  try {
    const emailPrefix = email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
    const composePath = path.join('/opt/quantum-rap-clients', emailPrefix, 'docker-compose.yml');
    if (!fs.existsSync(composePath)) return null;

    const content = fs.readFileSync(composePath, 'utf8');
    const appPortMatch = content.match(/ports:\s*\n\s*-\s*'(\d+):5000'/);
    return appPortMatch ? Number(appPortMatch[1]) : null;
  } catch (err) {
    console.error(`Error reading tenant port for ${email}:`, err);
    return null;
  }
}

// GET /api/auth/me
export const me = async (req: any, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }

  const isAdminNode = process.env.IS_ADMIN_NODE === 'true';
  let tenantPort: number | null = null;
  if (isAdminNode && req.user.role !== 'admin') {
    tenantPort = getTenantPort(req.user.email);
  }

  res.json({
    success: true,
    user: {
      id: req.user.id,
      email: req.user.email,
      role: req.user.role,
      isAdminNode,
      tenantPort,
    }
  });
};
