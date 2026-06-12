import { Router } from 'express';
import { 
  getAssets, 
  registerAssets, 
  deleteAsset, 
  scanFile, 
  scanConfig, 
  scanUrl 
} from '../controllers/assetController';
import { 
  syncVaultCertificates, 
  syncADCSCertificates 
} from '../controllers/caController';
import { getComplianceReport } from '../controllers/complianceController';
import { getAIChatResponse } from '../controllers/aiController';
import { 
  register, 
  login, 
  logout, 
  me,
  verify
} from '../controllers/authController';
import { 
  getClients, 
  provisionClient, 
  getClientStats, 
  decommissionClient,
  getUsers,
  toggleUserCMDB,
  toggleUserLock
} from '../controllers/adminController';
import { authenticateToken, requireAdmin, restrictClientOnAdminNode, rejectOnAdminNode } from '../utils/authMiddleware';

const router = Router();

// Authentication Gateways
router.post('/auth/register', register);
router.post('/auth/login', login);
router.get('/auth/verify', verify);
router.post('/auth/logout', authenticateToken, logout);
router.get('/auth/me', authenticateToken, me);

// Asset CRUD
router.get('/assets', authenticateToken, restrictClientOnAdminNode, getAssets);
router.post('/assets', rejectOnAdminNode, registerAssets); // Kept open for Go CLI scanner integration
router.delete('/assets/:id', authenticateToken, restrictClientOnAdminNode, deleteAsset);

// Scan endpoints
router.post('/scan/file', authenticateToken, restrictClientOnAdminNode, scanFile);
router.post('/scan/config', authenticateToken, restrictClientOnAdminNode, scanConfig);
router.post('/scan/url', authenticateToken, restrictClientOnAdminNode, scanUrl);

// CA Integrations
router.post('/ca/vault/sync', authenticateToken, restrictClientOnAdminNode, syncVaultCertificates);
router.post('/ca/adcs/sync', rejectOnAdminNode, syncADCSCertificates); // Kept open for Windows CA PowerShell sync agent

// Compliance & AI Chatbot
router.get('/compliance', authenticateToken, restrictClientOnAdminNode, getComplianceReport);
router.post('/ai/chat', authenticateToken, restrictClientOnAdminNode, getAIChatResponse);

// Admin Orchestration (Master Portal Only)
router.get('/admin/clients', authenticateToken, requireAdmin, getClients);
router.post('/admin/clients', authenticateToken, requireAdmin, provisionClient);
router.get('/admin/clients/:name/stats', authenticateToken, requireAdmin, getClientStats);
router.delete('/admin/clients/:name', authenticateToken, requireAdmin, decommissionClient);
router.get('/admin/users', authenticateToken, requireAdmin, getUsers);
router.post('/admin/users/:id/cmdb', authenticateToken, requireAdmin, toggleUserCMDB);
router.post('/admin/users/:id/lock', authenticateToken, requireAdmin, toggleUserLock);

export default router;
