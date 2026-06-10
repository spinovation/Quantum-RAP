import { Request, Response } from 'express';
import { exec } from 'child_process';
import fs from 'fs';
import path from 'path';
import { Pool } from 'pg';
import pool from '../config/db';
import { sendPortalProvisionedEmail } from '../utils/mailer';

const CLIENTS_ROOT = '/opt/quantum-rap-clients';
const PROVISION_SCRIPT = '/opt/quantum-rap/provision_client.sh';

interface ClientInfo {
  name: string;
  appPort: number;
  dbPort: number;
  status: 'active' | 'offline';
  createdAt: Date;
}

async function replicateUserToTenantDb(
  clientName: string,
  dbPort: number,
  userRow: { email: string; password_hash: string; salt: string; role: string }
): Promise<boolean> {
  const maxRetries = 15;
  const retryIntervalMs = 2000;
  let attempt = 0;

  while (attempt < maxRetries) {
    attempt++;
    console.log(`Replicating user ${userRow.email} to tenant database ${clientName} (attempt ${attempt}/${maxRetries})...`);
    let tempPool: Pool | null = null;
    try {
      tempPool = new Pool({
        user: 'postgres',
        host: 'host.docker.internal',
        database: `quarkshield_${clientName}`,
        password: 'postgres',
        port: dbPort,
        connectionTimeoutMillis: 3000
      });

      const client = await tempPool.connect();
      // First check if the users table exists (it might not be created yet if migrations are still running)
      const tableCheck = await client.query(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users')"
      );

      if (!tableCheck.rows[0].exists) {
        console.log(`Table 'users' does not exist yet in ${clientName} DB. Retrying...`);
        client.release();
        await tempPool.end();
        await new Promise(resolve => setTimeout(resolve, retryIntervalMs));
        continue;
      }

      // Insert the user
      await client.query(
        `INSERT INTO users (email, password_hash, salt, role, email_verified)
         VALUES ($1, $2, $3, $4, true)
         ON CONFLICT (email) DO UPDATE SET password_hash = $2, salt = $3, role = $4`,
        [userRow.email, userRow.password_hash, userRow.salt, userRow.role]
      );

      console.log(`Successfully replicated user ${userRow.email} to tenant database ${clientName}.`);
      client.release();
      await tempPool.end();
      return true; // Success!
    } catch (err: any) {
      console.warn(`Attempt ${attempt} to connect/insert to client DB ${clientName} failed: ${err.message}`);
      if (tempPool) {
        try {
          await tempPool.end();
        } catch (e) {}
      }
      await new Promise(resolve => setTimeout(resolve, retryIntervalMs));
    }
  }

  console.error(`Failed to replicate user ${userRow.email} to tenant database ${clientName} after ${maxRetries} attempts.`);
  return false;
}

// Helper: Parse docker-compose.yml to extract ports
function getPortsFromCompose(clientName: string): { appPort: number; dbPort: number } | null {
  try {
    const composePath = path.join(CLIENTS_ROOT, clientName, 'docker-compose.yml');
    if (!fs.existsSync(composePath)) return null;

    const content = fs.readFileSync(composePath, 'utf8');
    
    // Find app port mapping (e.g. - '5001:5000' or '127.0.0.1:5001:5000')
    const appPortMatch = content.match(/ports:\s*\n\s*-\s*'(?:127\.0\.0\.1:)?(\d+):5000'/);
    // Find db port mapping (e.g. - '5433:5432' or '127.0.0.1:5433:5432')
    const dbPortMatch = content.match(/ports:\s*\n\s*-\s*'(?:127\.0\.0\.1:)?(\d+):5432'/);

    return {
      appPort: appPortMatch ? Number(appPortMatch[1]) : 0,
      dbPort: dbPortMatch ? Number(dbPortMatch[1]) : 0
    };
  } catch (err) {
    console.error(`Error parsing ports for client ${clientName}:`, err);
    return null;
  }
}

// GET /api/admin/clients
export const getClients = async (req: Request, res: Response) => {
  try {
    if (!fs.existsSync(CLIENTS_ROOT)) {
      return res.json([]);
    }

    const dirs = fs.readdirSync(CLIENTS_ROOT).filter(file => {
      const fullPath = path.join(CLIENTS_ROOT, file);
      return fs.statSync(fullPath).isDirectory();
    });

    const clients: ClientInfo[] = [];

    for (const dir of dirs) {
      const ports = getPortsFromCompose(dir);
      if (ports) {
        // Retrieve creation date of the client folder
        const stats = fs.statSync(path.join(CLIENTS_ROOT, dir));
        
        clients.push({
          name: dir,
          appPort: ports.appPort,
          dbPort: ports.dbPort,
          status: 'active', // Will be verified dynamically by logs or stats
          createdAt: stats.birthtime
        });
      }
    }

    res.json(clients);
  } catch (err: any) {
    console.error('Error fetching client list:', err);
    res.status(500).json({ error: `Failed to fetch client list: ${err.message}` });
  }
};

// POST /api/admin/clients
export const provisionClient = async (req: Request, res: Response) => {
  try {
    const { name, appPort, dbPort, geminiApiKey, email } = req.body;
    if (!name || !appPort || !dbPort) {
      return res.status(400).json({ error: 'Missing name, appPort, or dbPort.' });
    }

    // Sanitize name to alphanumeric lowercase
    const sanitizedName = name.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (sanitizedName.length < 3) {
      return res.status(400).json({ error: 'Client name must be at least 3 alphanumeric characters.' });
    }

    // Verify ports are valid numbers
    const appP = Number(appPort);
    const dbP = Number(dbPort);
    if (isNaN(appP) || isNaN(dbP) || appP < 1024 || appP > 65535 || dbP < 1024 || dbP > 65535) {
      return res.status(400).json({ error: 'Invalid port numbers. Must be between 1024 and 65535.' });
    }

    // Check if client folder already exists
    const clientPath = path.join(CLIENTS_ROOT, sanitizedName);
    if (fs.existsSync(clientPath)) {
      return res.status(400).json({ error: `Client '${sanitizedName}' already exists on this server.` });
    }

    // If email is provided, verify they exist in master DB and retrieve credentials
    let userRow: any = null;
    if (email) {
      const userRes = await pool.query('SELECT email, password_hash, salt, role FROM users WHERE email = $1', [email]);
      if (userRes.rows.length === 0) {
        return res.status(400).json({ error: `User with email '${email}' not found in master database.` });
      }
      userRow = userRes.rows[0];
    }

    const geminiKey = geminiApiKey ? geminiApiKey.trim() : '';

    // Execute provision script on the host via mounted script path
    const command = `${PROVISION_SCRIPT} ${sanitizedName} ${appP} ${dbP} "${geminiKey}"`;
    console.log(`Executing provisioning command: ${command}`);

    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error('Provisioning script error:', error);
        console.error('Stderr:', stderr);
        return res.status(500).json({ error: `Provisioning failed: ${stderr || error.message}` });
      }

      console.log('Provisioning stdout:', stdout);
      const reqHost = req.get('x-forwarded-host') || req.get('host') || 'localhost:5000';
      const hostname = reqHost.split(':')[0];
      const protocol = req.get('x-forwarded-proto') || req.protocol || 'http';
      const portalUrl = protocol === 'https'
        ? `https://${sanitizedName}.${hostname}`
        : `http://${hostname}:${appP}`;

      if (email && userRow) {
        replicateUserToTenantDb(sanitizedName, dbP, userRow).then((success) => {
          if (success) {
            console.log(`Sending provisioning email to: ${email}`);
            sendPortalProvisionedEmail(email, sanitizedName, portalUrl, dbP).catch(mailErr => {
              console.error(`Failed to send portal provisioned email to ${email}:`, mailErr);
            });
          } else {
            console.error(`Not sending provisioning email to ${email} because user replication failed.`);
          }
        });
      }

      res.status(201).json({
        success: true,
        message: `Client '${sanitizedName}' successfully provisioned. Seeding client user credentials in the background.`,
        client: {
          name: sanitizedName,
          appPort: appP,
          dbPort: dbP,
          url: portalUrl
        }
      });
    });
  } catch (err: any) {
    console.error('Provision client error:', err);
    res.status(500).json({ error: `Failed to provision client: ${err.message}` });
  }
};

// GET /api/admin/users
export const getUsers = async (req: Request, res: Response) => {
  try {
    const result = await pool.query(
      'SELECT id, email, role, email_verified, created_at FROM users WHERE role = $1 ORDER BY created_at DESC',
      ['user']
    );
    res.json(result.rows);
  } catch (err: any) {
    console.error('Error fetching registered users:', err);
    res.status(500).json({ error: `Failed to fetch registered users: ${err.message}` });
  }
};

// GET /api/admin/clients/:name/stats
export const getClientStats = async (req: Request, res: Response) => {
  let tempPool: Pool | null = null;
  try {
    const { name } = req.params;
    const ports = getPortsFromCompose(name);
    if (!ports) {
      return res.status(404).json({ error: `Client configuration for '${name}' not found.` });
    }

    // Connect to client database over the host bridge interface (host.docker.internal)
    tempPool = new Pool({
      user: 'postgres',
      host: 'host.docker.internal',
      database: `quarkshield_${name}`,
      password: 'postgres',
      port: ports.dbPort,
      connectionTimeoutMillis: 3000 // Short timeout to avoid blocking if client DB is starting
    });

    let userCount = 0;
    let assetCount = 0;
    let isConnected = false;

    try {
      const client = await tempPool.connect();
      isConnected = true;

      // Query user count
      const userRes = await client.query('SELECT COUNT(*) FROM users');
      userCount = Number(userRes.rows[0].count);

      // Query asset count
      const assetRes = await client.query('SELECT COUNT(*) FROM assets');
      assetCount = Number(assetRes.rows[0].count);

      client.release();
    } catch (connErr) {
      console.warn(`Failed to connect to client database '${name}' on port ${ports.dbPort}:`, connErr);
    }

    res.json({
      name,
      appPort: ports.appPort,
      dbPort: ports.dbPort,
      status: isConnected ? 'active' : 'offline',
      userCount,
      assetCount
    });

  } catch (err: any) {
    console.error(`Error querying stats for client:`, err);
    res.status(500).json({ error: `Stats query failed: ${err.message}` });
  } finally {
    if (tempPool) {
      await tempPool.end();
    }
  }
};

// DELETE /api/admin/clients/:name
export const decommissionClient = async (req: Request, res: Response) => {
  try {
    const { name } = req.params;
    const clientPath = path.join(CLIENTS_ROOT, name);
    
    if (!fs.existsSync(clientPath)) {
      return res.status(404).json({ error: `Client '${name}' not found.` });
    }

    // Run docker compose down -v to stop containers and delete DB volume on host
    const command = `cd ${clientPath} && docker compose down -v`;
    console.log(`Executing decommission command: ${command}`);

    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error('Decommission error:', error);
        return res.status(500).json({ error: `Failed to stop containers: ${error.message}` });
      }

      // Remove the client configuration directory
      try {
        fs.rmSync(clientPath, { recursive: true, force: true });
        res.json({ success: true, message: `Client '${name}' successfully decommissioned and data wiped.` });
      } catch (rmErr: any) {
        console.error('Error removing client directory:', rmErr);
        res.status(500).json({ error: `Containers stopped, but failed to delete directory: ${rmErr.message}` });
      }
    });

  } catch (err: any) {
    console.error('Decommission client error:', err);
    res.status(500).json({ error: `Decommission failed: ${err.message}` });
  }
};
