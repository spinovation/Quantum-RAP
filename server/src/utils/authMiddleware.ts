import { Request, Response, NextFunction } from 'express';
import pool from '../config/db';

// Extends express Request type to include user context
export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: string;
  };
}

export const authenticateToken = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authentication token required.' });
    }

    const token = authHeader.split(' ')[1];
    
    // Query session details and join user profiles
    const sessionResult = await pool.query(
      'SELECT s.expires_at, u.id, u.email, u.role FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = $1',
      [token]
    );

    if (sessionResult.rowCount === 0) {
      return res.status(401).json({ error: 'Invalid or expired session.' });
    }

    const session = sessionResult.rows[0];
    const now = new Date();

    if (new Date(session.expires_at) < now) {
      // Clean up expired session automatically
      await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    }

    // Attach user to context
    req.user = {
      id: session.id,
      email: session.email,
      role: session.role
    };

    next();
  } catch (err: any) {
    console.error('Authentication error:', err);
    res.status(500).json({ error: 'Internal server authorization check failed.' });
  }
};

export const requireAdmin = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Administrative privileges required.' });
  }
  next();
};

export const restrictClientOnAdminNode = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  if (process.env.IS_ADMIN_NODE === 'true' && req.user && req.user.role !== 'admin') {
    return res.status(403).json({ 
      error: 'Access Denied: Scanning and risk audit features are restricted on the master control node for client accounts. Please access your dedicated tenant portal URL.',
      code: 'RESTRICTED_ON_ADMIN_NODE'
    });
  }
  next();
};

export const rejectOnAdminNode = (req: Request, res: Response, next: NextFunction) => {
  if (process.env.IS_ADMIN_NODE === 'true') {
    return res.status(403).json({ 
      error: 'Endpoint disabled on the master control node. Please run scanner/sync agents against your dedicated client node port.' 
    });
  }
  next();
};
