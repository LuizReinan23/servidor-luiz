import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import Database from 'better-sqlite3';
import multer from 'multer';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = 3000;

// Path configuration for persistence (Railway/Docker support)
const DATA_DIR = process.env.DATABASE_URL 
  ? path.dirname(process.env.DATABASE_URL) 
  : process.cwd();

const DB_PATH = process.env.DATABASE_URL || path.join(process.cwd(), 'database.db');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const JWT_SECRET = process.env.JWT_SECRET || 'fibra-controle-projetos-secret-key-2024';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

app.use((req, res, next) => {
  if (req.path.startsWith('/api')) {
    console.log(`${req.method} ${req.path}`);
  }
  next();
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Ensure uploads directory exists
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Database Setup
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Initialize Tables
db.exec(`
  CREATE TABLE IF NOT EXISTS work_orders (
    id TEXT PRIMARY KEY,
    projeto TEXT NOT NULL,
    ordem TEXT,
    cliente TEXT,
    bairro TEXT NOT NULL,
    prazo TEXT,
    inicio TEXT NOT NULL,
    fim TEXT,
    observacao TEXT,
    equipe TEXT NOT NULL,
    status TEXT NOT NULL,
    prioridade TEXT,
    tipo_servico TEXT,
    source TEXT DEFAULT 'MANUAL',
    telefone TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ordem)
  );

  CREATE TABLE IF NOT EXISTS service_types (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS custom_statuses (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    color TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS erp_config (
    id TEXT PRIMARY KEY DEFAULT 'default',
    api_url TEXT,
    api_token TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'LEITOR',
    status TEXT DEFAULT 'PENDENTE',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Migration: Add role and status columns to users if they don't exist
try {
  db.prepare('ALTER TABLE users ADD COLUMN role TEXT DEFAULT "LEITOR"').run();
} catch (e) {}
try {
  db.prepare('ALTER TABLE users ADD COLUMN status TEXT DEFAULT "PENDENTE"').run();
} catch (e) {}

// Migration: Seed default statuses
try {
  const statusCount = db.prepare('SELECT COUNT(*) as count FROM custom_statuses').get() as any;
  if (statusCount.count === 0) {
    const defaultStatuses = [
      'PENDENTE',
      'EM_ANDAMENTO',
      'CONCLUIDO',
      'BLOQUEADO',
      'CANCELADO',
      'ABERTA',
      'REAGENDAMENTO',
      'AGENDADA'
    ];
    const insert = db.prepare('INSERT INTO custom_statuses (id, name) VALUES (?, ?)');
    defaultStatuses.forEach(name => {
      insert.run(uuidv4(), name);
    });
    console.log('Default statuses seeded.');
  }
} catch (e) {
  console.error('Error seeding statuses:', e);
}

// Ensure at least one admin exists if there are users
try {
  const users = db.prepare('SELECT * FROM users').all();
  if (users.length > 0) {
    const admins = db.prepare("SELECT * FROM users WHERE role = 'ADMIN'").all();
    if (admins.length === 0) {
      // Make the first user an admin and active
      db.prepare("UPDATE users SET role = 'ADMIN', status = 'ATIVO' WHERE id = ?").run(users[0].id);
    }
  }
} catch (e) {}

// Migration: Ensure specific user is admin
try {
  const result = db.prepare("UPDATE users SET role = 'ADMIN', status = 'ATIVO' WHERE email = 'luiz.reinan@gmail.com'").run();
  if (result.changes > 0) {
    console.log('User luiz.reinan@gmail.com updated to ADMIN');
  }
} catch (e) {
  console.error('Error in admin migration:', e);
}

// Migration: Add source column to work_orders if it doesn't exist
try {
  db.prepare('ALTER TABLE work_orders ADD COLUMN source TEXT DEFAULT "MANUAL"').run();
} catch (e) {}

// Migration: Add telefone column to work_orders if it doesn't exist
try {
  db.prepare('ALTER TABLE work_orders ADD COLUMN telefone TEXT').run();
} catch (e) {}

// Migration: Add unique index to ordem if it doesn't exist
try {
  db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_work_orders_ordem ON work_orders(ordem)').run();
} catch (e) {}

db.exec(`
  -- Insert default ERP config if empty
  INSERT OR IGNORE INTO erp_config (id) VALUES ('default');

  -- Insert default service types if table is empty
  INSERT OR IGNORE INTO service_types (id, name) VALUES 
    ('1', 'CTO'),
    ('2', 'PASSAGEM_CABO'),
    ('3', 'SPLITTER'),
    ('4', 'VIABILIDADE'),
    ('5', 'EXPANSAO'),
    ('6', 'MANUTENCAO'),
    ('7', 'OUTRO');

  CREATE TABLE IF NOT EXISTS work_order_files (
    id TEXT PRIMARY KEY,
    work_order_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_type TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    storage_path TEXT NOT NULL,
    public_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (work_order_id) REFERENCES work_orders(id) ON DELETE CASCADE
  );
`);

app.use(express.json());
app.use('/uploads', express.static(UPLOADS_DIR));

// Multer Setup for File Uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const { ordem } = req.params;
    const dir = path.join(UPLOADS_DIR, ordem);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Preencha todos os campos.' });
  }

  try {
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get() as any;
    const isFirstUser = userCount.count === 0;
    const isSpecialAdmin = email.toLowerCase() === 'luiz.reinan@gmail.com';
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const role = (isFirstUser || isSpecialAdmin) ? 'ADMIN' : 'LEITOR';
    const status = (isFirstUser || isSpecialAdmin) ? 'ATIVO' : 'PENDENTE';

    db.prepare('INSERT INTO users (id, name, email, password, role, status) VALUES (?, ?, ?, ?, ?, ?)').run(
      id, name, email, hashedPassword, role, status
    );
    
    const token = jwt.sign({ id, email, name, role, status }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id, name, email, role, status } });
  } catch (err: any) {
    if (err.message.includes('UNIQUE constraint failed: users.email')) {
      return res.status(400).json({ error: 'Este e-mail já está em uso.' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  console.log('Login attempt for:', req.body.email);
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Preencha todos os campos.' });
  }

  try {
    // Case-insensitive search
    let user = db.prepare('SELECT * FROM users WHERE LOWER(email) = LOWER(?)').get(email) as any;
    
    if (!user) {
      console.log('User not found:', email);
      return res.status(400).json({ error: 'Usuário não encontrado.' });
    }

    // Fail-safe: Force activate the main admin if they are pending
    if (user.email.toLowerCase() === 'luiz.reinan@gmail.com' && (user.status !== 'ATIVO' || user.role !== 'ADMIN')) {
      console.log('Force activating admin user:', user.email);
      db.prepare("UPDATE users SET role = 'ADMIN', status = 'ATIVO' WHERE id = ?").run(user.id);
      // Refresh user data
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id) as any;
    }

    console.log('User found:', user.email, 'Status:', user.status, 'Role:', user.role);

    if (user.status === 'PENDENTE') {
      return res.status(401).json({ error: 'Sua conta está aguardando aprovação de um administrador.' });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(400).json({ error: 'Senha incorreta.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: user.role, status: user.status }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, status: user.status } });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Não autorizado' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    let user = db.prepare('SELECT id, name, email, role, status FROM users WHERE id = ?').get(decoded.id) as any;
    if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });

    // Fail-safe for admin
    if (user.email.toLowerCase() === 'luiz.reinan@gmail.com' && (user.status !== 'ATIVO' || user.role !== 'ADMIN')) {
      db.prepare("UPDATE users SET role = 'ADMIN', status = 'ATIVO' WHERE id = ?").run(user.id);
      user = db.prepare('SELECT id, name, email, role, status FROM users WHERE id = ?').get(user.id) as any;
    }

    if (user.status === 'PENDENTE') return res.status(401).json({ error: 'Conta pendente' });
    res.json(user);
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
});

// User Management Routes (Admin Only)
const isAdmin = (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Não autorizado' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    if (decoded.role !== 'ADMIN') return res.status(401).json({ error: 'Acesso negado. Apenas administradores.' });
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
};

app.get('/api/users', isAdmin, (req, res) => {
  const users = db.prepare('SELECT id, name, email, role, status, created_at FROM users ORDER BY created_at DESC').all();
  res.json(users);
});

app.put('/api/users/:id', isAdmin, (req, res) => {
  const { role, status } = req.body;
  try {
    db.prepare('UPDATE users SET role = ?, status = ? WHERE id = ?').run(role, status, req.params.id);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/users/:id', isAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// API Routes
app.get('/api/work-orders', (req, res) => {
  const orders = db.prepare('SELECT * FROM work_orders ORDER BY created_at DESC').all();
  res.json(orders);
});

app.get('/api/work-orders/:id', (req, res) => {
  const order = db.prepare('SELECT * FROM work_orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  const files = db.prepare('SELECT * FROM work_order_files WHERE work_order_id = ?').all(req.params.id);
  res.json({ ...order, work_order_files: files });
});

app.post('/api/work-orders', (req, res) => {
  const id = uuidv4();
  const { projeto, ordem, cliente, bairro, prazo, inicio, fim, observacao, equipe, status, prioridade, tipo_servico } = req.body;
  
  try {
    const stmt = db.prepare(`
      INSERT INTO work_orders (id, projeto, ordem, cliente, bairro, prazo, inicio, fim, observacao, equipe, status, prioridade, tipo_servico)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(id, projeto, ordem, cliente, bairro, prazo, inicio, fim, observacao, equipe, status, prioridade, tipo_servico);
    const newOrder = db.prepare('SELECT * FROM work_orders WHERE id = ?').get(id);
    res.json(newOrder);
  } catch (err: any) {
    if (err.message.includes('UNIQUE constraint failed')) {
      return res.status(400).json({ error: 'Já existe uma O.S com este número de ordem.' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/work-orders/:id', (req, res) => {
  const fields = Object.keys(req.body).filter(k => k !== 'id' && k !== 'created_at');
  const values = fields.map(k => req.body[k]);
  const setClause = fields.map(k => `${k} = ?`).join(', ');
  
  try {
    db.prepare(`UPDATE work_orders SET ${setClause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
      .run(...values, req.params.id);
    const updated = db.prepare('SELECT * FROM work_orders WHERE id = ?').get(req.params.id);
    res.json(updated);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/work-orders/:id', (req, res) => {
  const { id } = req.params;
  console.log(`Deletando ordem de serviço: ${id}`);
  try {
    const result = db.prepare('DELETE FROM work_orders WHERE id = ?').run(id);
    console.log(`Resultado da deleção: ${result.changes} linhas removidas.`);
    res.json({ success: true, changes: result.changes });
  } catch (err: any) {
    console.error(`Erro ao deletar ordem ${id}:`, err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/work-orders/:id/files/:ordem', upload.array('files'), (req, res) => {
  const files = req.files as Express.Multer.File[];
  const work_order_id = req.params.id;
  const results = [];

  for (const file of files) {
    const id = uuidv4();
    const public_url = `/uploads/${req.params.ordem}/${file.filename}`;
    db.prepare(`
      INSERT INTO work_order_files (id, work_order_id, file_name, file_type, file_size, storage_path, public_url)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, work_order_id, file.originalname, file.mimetype, file.size, file.path, public_url);
    results.push(db.prepare('SELECT * FROM work_order_files WHERE id = ?').get(id));
  }
  res.json(results);
});

app.delete('/api/files/:id', (req, res) => {
  const file = db.prepare('SELECT * FROM work_order_files WHERE id = ?').get(req.params.id) as any;
  if (file) {
    if (fs.existsSync(file.storage_path)) {
      fs.unlinkSync(file.storage_path);
    }
    db.prepare('DELETE FROM work_order_files WHERE id = ?').run(req.params.id);
  }
  res.json({ success: true });
});

// Service Types Routes
app.get('/api/service-types', (req, res) => {
  const types = db.prepare('SELECT * FROM service_types ORDER BY name ASC').all();
  res.json(types);
});

app.post('/api/service-types', (req, res) => {
  const id = uuidv4();
  const { name } = req.body;
  try {
    db.prepare('INSERT INTO service_types (id, name) VALUES (?, ?)').run(id, name);
    const newType = db.prepare('SELECT * FROM service_types WHERE id = ?').get(id);
    res.json(newType);
  } catch (err: any) {
    res.status(400).json({ error: 'Tipo de serviço já existe.' });
  }
});

// Custom Statuses Routes
app.get('/api/statuses', (req, res) => {
  const statuses = db.prepare('SELECT * FROM custom_statuses ORDER BY name ASC').all();
  res.json(statuses);
});

app.post('/api/statuses', (req, res) => {
  const id = uuidv4();
  const { name } = req.body;
  try {
    db.prepare('INSERT INTO custom_statuses (id, name) VALUES (?, ?)').run(id, name);
    const newStatus = db.prepare('SELECT * FROM custom_statuses WHERE id = ?').get(id);
    res.json(newStatus);
  } catch (err: any) {
    res.status(400).json({ error: 'Status já existe.' });
  }
});

// Hardcoded ERP Credentials (as requested)
const IXC_API_URL = 'https://central.r3internet.com.br/webservice/v1/su_oss_chamado';
const IXC_API_TOKEN = '35:1591f43b70871e2b08e2ca30b63c323cac5a180239a43439c8f463e094dc6d7e';

// ERP Config Routes
app.get('/api/erp-config', (req, res) => {
  // Return hardcoded values info
  res.json({ 
    api_url: 'Configurado no Backend', 
    api_token: '••••••••••••••••',
    is_hardcoded: true
  });
});

app.post('/api/erp-config', (req, res) => {
  // Disable saving if hardcoded, or just pretend it worked
  res.json({ success: true, message: 'Configurações gerenciadas pelo backend.' });
});

app.post('/api/erp-sync', async (req, res) => {
  try {
    let url;
    try {
      url = new URL(IXC_API_URL);
    } catch (e) {
      return res.status(400).json({ error: 'A URL hardcoded no backend é inválida.' });
    }

    console.log(`Iniciando sincronização POST com IXC (Config Postman): ${url.toString()}`);
    
    const authHeader = `Basic ${Buffer.from(IXC_API_TOKEN).toString('base64')}`;
    
    // Using the exact body provided by the user
    const body = {
      "qtype": "su_oss_chamado.tipo",
      "query": "E",
      "oper": "=",
      "page": "1",
      "rp": "1000",
      "sortname": "su_oss_chamado.id",
      "sortorder": "desc"
    };

    const response = await fetch(url.toString(), {
      method: 'POST',
      headers: {
        'Authorization': authHeader,
        'ixcsoft': 'listar',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });

    const responseText = await response.text();
    
    if (!response.ok) {
      console.error(`Erro do ERP (${response.status}):`, responseText.substring(0, 200));
      return res.status(response.status).json({ 
        error: `O ERP retornou erro ${response.status}.`,
        details: responseText.substring(0, 100)
      });
    }

    let data;
    try {
      data = JSON.parse(responseText);
    } catch (e) {
      console.error('Resposta não-JSON do ERP:', responseText.substring(0, 200));
      return res.status(500).json({ 
        error: 'A resposta do ERP não é um JSON válido.',
        details: responseText.substring(0, 100)
      });
    }
    
    // Handle different IXC response formats
    let registros = [];
    if (Array.isArray(data)) {
      registros = data;
    } else if (data.registros && Array.isArray(data.registros)) {
      registros = data.registros;
    } else if (data.rows && Array.isArray(data.rows)) {
      registros = data.rows;
    } else if (data.data && Array.isArray(data.data)) {
      registros = data.data;
    }

    if (registros.length === 0) {
      console.log('Nenhum registro encontrado na resposta:', JSON.stringify(data).substring(0, 200));
      return res.json({ 
        message: 'Sincronização concluída, mas nenhuma ordem foi encontrada.', 
        details: 'O ERP retornou uma lista vazia ou em um formato não reconhecido.',
        count: 0 
      });
    }

    let importedCount = 0;
    let skippedCount = 0;

    const importedIds: string[] = [];

    for (const reg of registros) {
      // Map fields carefully based on the user's screenshot
      const item = reg.cell ? reg.cell : reg;
      
      // Filter by status: A (Aberta), AG (Agendada), RAG (Aguardando Reagendamento)
      const erpStatus = item.status?.toString().toUpperCase();
      if (erpStatus !== 'A' && erpStatus !== 'AG' && erpStatus !== 'RAG') {
        continue;
      }

      const id = uuidv4();
      const ordem = item.id?.toString() || item.numero_ordem || '';
      const projeto = item.assunto || item.titulo || 'Sem Assunto';
      const clienteId = item.id_cliente || item.cliente_id || item.id_contato || '0';
      const cliente = `ID: ${clienteId}`;
      const bairro = item.bairro || 'N/A';
      const telefone = item.telefone_celular || item.telefone || item.celular || '-';
      const inicio = (item.data_abertura || item.data_cadastro || '').split(' ')[0] || new Date().toISOString().split('T')[0];
      const equipe = item.id_tecnico_responsavel || item.tecnico || 'EQUIPE ERP';
      
      // Map ERP status to our internal status
      let status = 'ABERTA';
      if (erpStatus === 'AG') status = 'AGENDADA';
      if (erpStatus === 'RAG') status = 'REAGENDAMENTO';
      
      const tipo_servico = item.tipo_servico || 'MANUTENCAO';
      const source = 'ERP';
      const observacao = item.mensagem || item.descricao || '';

      if (!ordem) continue;

      try {
        const result = db.prepare(`
          INSERT INTO work_orders (id, projeto, ordem, cliente, bairro, inicio, equipe, status, tipo_servico, source, observacao, telefone)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(ordem) DO UPDATE SET
            projeto = excluded.projeto,
            cliente = excluded.cliente,
            bairro = excluded.bairro,
            inicio = excluded.inicio,
            equipe = excluded.equipe,
            status = excluded.status,
            observacao = excluded.observacao,
            telefone = excluded.telefone,
            updated_at = CURRENT_TIMESTAMP
        `).run(id, projeto, ordem, cliente, bairro, inicio, equipe, status, tipo_servico, source, observacao, telefone);
        
        if (result.changes > 0) {
          importedCount++;
          importedIds.push(ordem);
        } else {
          skippedCount++;
        }
      } catch (e) {
        console.error('Erro ao inserir/atualizar ordem:', e);
        skippedCount++;
      }
    }

    // Cleanup: Remove ERP orders that were NOT in the current sync batch
    // This ensures that orders finished/canceled in IXC are removed from our app
    if (importedIds.length > 0) {
      const placeholders = importedIds.map(() => '?').join(',');
      db.prepare(`
        DELETE FROM work_orders 
        WHERE source = 'ERP' 
        AND ordem NOT IN (${placeholders})
      `).run(...importedIds);
    } else if (registros.length > 0) {
      // If we got records but none matched our filter, clear all ERP orders
      db.prepare("DELETE FROM work_orders WHERE source = 'ERP'").run();
    }

    res.json({ 
      message: `Sincronização concluída com sucesso!`, 
      details: `${importedCount} novas ordens importadas, ${skippedCount} já existiam.`,
      count: importedCount 
    });
  } catch (err: any) {
    console.error('Erro na sincronização:', err);
    res.status(500).json({ error: 'Erro de conexão: ' + err.message });
  }
});

// Global Error Handler
app.use((err: any, req: any, res: any, next: any) => {
  console.error('Server Error:', err);
  res.status(500).json({ error: 'Erro interno do servidor: ' + err.message });
});

// Vite Integration
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(process.cwd(), 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.join(process.cwd(), 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
