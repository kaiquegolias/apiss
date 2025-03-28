import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import expressSession from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import swaggerUi from 'swagger-ui-express';
import swaggerJsDoc from 'swagger-jsdoc';
import { supabase } from './supabase.js';

const app = express();
const PgSession = connectPgSimple(expressSession);

// =============================================
// Configuração Básica do Express
// =============================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// =============================================
// Configuração de Sessão
// =============================================
app.use(
  expressSession({
    store: new PgSession({
      conString: process.env.SUPABASE_DB_URL,
      tableName: 'user_sessions',
      createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET || 'fallback-secret-dev',
    resave: false,
    saveUninitialized: false,
    cookie: { 
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 dias
      httpOnly: true,
      sameSite: 'lax'
    }
  })
);

// =============================================
// Middlewares
// =============================================
app.use(async (req, res, next) => {
  try {
    const { data, error } = await supabase.from('usuarios').select('*').limit(1);
    if (error) throw error;
    next();
  } catch (error) {
    console.error('Erro ao conectar ao banco de dados:', error.message);
    res.status(500).json({ error: 'Erro de conexão com o banco de dados' });
  }
});

const verificarAutenticacao = (req, res, next) => {
  const token = req.session.token || req.cookies.session_token;
  if (!token) return res.status(401).json({ error: 'Usuário não autenticado' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret-fallback');
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido ou expirado' });
  }
};

const verificarSupervisor = (req, res, next) => {
  if (req.user.nivel_acesso !== 'supervisor') {
    return res.status(403).json({ error: 'Acesso restrito a supervisores' });
  }
  next();
};

// =============================================
// Swagger Configuration (Completa)
// =============================================
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API de Monitoramento',
      version: '1.0.0',
      description: 'API completa para gerenciamento de operadores e supervisores',
    },
    servers: [
      {
        url: process.env.RENDER_EXTERNAL_URL || `http://localhost:${process.env.PORT || 3000}`,
        description: 'Servidor Principal'
      }
    ],
    components: {
      securitySchemes: {
        sessionAuth: {
          type: 'apiKey',
          in: 'cookie',
          name: 'connect.sid'
        }
      }
    }
  },
  apis: ['./index.js']
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs, {
  explorer: true,
  customSiteTitle: 'API de Monitoramento'
}));

// =============================================
// Rotas de Autenticação (Completas)
// =============================================

/**
 * @swagger
 * /auth/login-operador:
 *   post:
 *     tags: [Autenticação]
 *     summary: Login para operadores
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               senha:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login bem-sucedido
 */
app.post('/auth/login-operador', async (req, res) => {
  try {
    const { email, senha } = req.body;
    const { data: user, error } = await supabase
      .from('usuarios')
      .select('*')
      .eq('email', email)
      .single();

    if (!user || error || user.nivel_acesso !== 'operador') {
      return res.status(400).json({ error: 'Credenciais inválidas para operador' });
    }

    const senhaValida = await bcrypt.compare(senha, user.senha);
    if (!senhaValida) return res.status(400).json({ error: 'Credenciais inválidas' });

    const token = jwt.sign(
      { userId: user.id, nivel_acesso: user.nivel_acesso },
      process.env.JWT_SECRET || 'dev-secret-fallback',
      { expiresIn: '8h' }
    );

    req.session.token = token;
    res.cookie('session_token', token, { 
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 8 * 60 * 60 * 1000
    });

    res.json({ 
      message: 'Login de operador bem-sucedido',
      userId: user.id,
      nivel_acesso: user.nivel_acesso
    });

  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno' });
  }
});

/**
 * @swagger
 * /auth/login-supervisor:
 *   post:
 *     tags: [Autenticação]
 *     summary: Login para supervisores
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               senha:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login bem-sucedido
 */
app.post('/auth/login-supervisor', async (req, res) => {
  try {
    const { email, senha } = req.body;
    const { data: user, error } = await supabase
      .from('usuarios')
      .select('*')
      .eq('email', email)
      .single();

    if (!user || error || user.nivel_acesso !== 'supervisor') {
      return res.status(400).json({ error: 'Credenciais inválidas para supervisor' });
    }

    const senhaValida = await bcrypt.compare(senha, user.senha);
    if (!senhaValida) return res.status(400).json({ error: 'Credenciais inválidas' });

    const token = jwt.sign(
      { userId: user.id, nivel_acesso: user.nivel_acesso },
      process.env.JWT_SECRET || 'dev-secret-fallback',
      { expiresIn: '8h' }
    );

    req.session.token = token;
    res.cookie('session_token', token, { 
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 8 * 60 * 60 * 1000
    });

    res.json({ 
      message: 'Login de supervisor bem-sucedido',
      userId: user.id,
      nivel_acesso: user.nivel_acesso
    });

  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// =============================================
// Rotas de Operador (Completas)
// =============================================

/**
 * @swagger
 * /operador/cadastrar:
 *   post:
 *     tags: [Supervisor]
 *     summary: Cadastra novo operador (apenas para supervisores)
 *     security:
 *       - sessionAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nome:
 *                 type: string
 *               email:
 *                 type: string
 *               senha:
 *                 type: string
 *     responses:
 *       201:
 *         description: Operador cadastrado
 */
app.post('/operador/cadastrar', verificarAutenticacao, verificarSupervisor, async (req, res) => {
  try {
    const { nome, email, senha } = req.body;
    const senhaHash = await bcrypt.hash(senha, 10);

    // Verifica se email já existe
    const { data: usuarioExistente } = await supabase
      .from('usuarios')
      .select('id')
      .eq('email', email)
      .single();

    if (usuarioExistente) {
      return res.status(400).json({ error: 'Email já cadastrado' });
    }

    const { data: novoOperador, error } = await supabase
      .from('usuarios')
      .insert({
        nome,
        email,
        senha: senhaHash,
        nivel_acesso: 'operador',
        supervisor_id: req.user.userId
      })
      .select()
      .single();

    if (error) throw error;

    // Cria registro inicial de monitoramento
    await supabase
      .from('monitoramento')
      .insert({ operador_id: novoOperador.id });

    res.status(201).json({ 
      message: 'Operador cadastrado com sucesso',
      operador_id: novoOperador.id
    });

  } catch (error) {
    console.error('Erro ao cadastrar operador:', error);
    res.status(500).json({ error: 'Erro ao cadastrar operador' });
  }
});

/**
 * @swagger
 * /operador/list:
 *   get:
 *     tags: [Supervisor]
 *     summary: Lista operadores do supervisor
 *     security:
 *       - sessionAuth: []
 *     responses:
 *       200:
 *         description: Lista de operadores
 */
app.get('/operador/list', verificarAutenticacao, verificarSupervisor, async (req, res) => {
  try {
    const { data: operadores, error } = await supabase
      .from('usuarios')
      .select(`
        id,
        nome,
        email,
        nivel_acesso,
        monitoramento:monitoramento(
          status_online
        )
      `)
      .eq('supervisor_id', req.user.userId);

    if (error) throw error;

    // Formata resposta incluindo status_online
    const resposta = operadores.map(op => ({
      ...op,
      status_online: op.monitoramento?.status_online || false
    }));

    res.status(200).json(resposta);
  } catch (error) {
    console.error('Erro ao listar operadores:', error);
    res.status(500).json({ error: 'Erro ao buscar operadores' });
  }
});

// =============================================
// Rotas de Monitoramento (Completas - Originais)
// =============================================

/**
 * @swagger
 * /monitoramento/{operadorId}:
 *   get:
 *     tags: [Supervisor]
 *     summary: Verifica status de um operador
 *     security:
 *       - sessionAuth: []
 *     parameters:
 *       - in: path
 *         name: operadorId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Dados de monitoramento
 */
app.get('/monitoramento/:operadorId', verificarAutenticacao, verificarSupervisor, async (req, res) => {
  try {
    const { operadorId } = req.params;

    // Verifica se operador pertence ao supervisor
    const { data: operador, error: opError } = await supabase
      .from('usuarios')
      .select('id, nome')
      .eq('id', operadorId)
      .eq('supervisor_id', req.user.userId)
      .single();

    if (!operador || opError) {
      return res.status(404).json({ error: 'Operador não encontrado' });
    }

    // Busca status
    const { data: monitoramento, error: monError } = await supabase
      .from('monitoramento')
      .select('*')
      .eq('operador_id', operadorId)
      .single();

    res.status(200).json({
      operador,
      status: monitoramento || { status_online: false }
    });

  } catch (error) {
    console.error('Erro no monitoramento:', error);
    res.status(500).json({ error: 'Erro ao buscar status' });
  }
});

/**
 * @swagger
 * /monitoramento/{operadorId}/status:
 *   put:
 *     tags: [Supervisor]
 *     summary: Atualiza status de um operador
 *     security:
 *       - sessionAuth: []
 *     parameters:
 *       - in: path
 *         name: operadorId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               status_online:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Status atualizado
 */
app.put('/monitoramento/:operadorId/status', verificarAutenticacao, verificarSupervisor, async (req, res) => {
  try {
    const { operadorId } = req.params;
    const { status_online } = req.body;

    // Verifica se operador pertence ao supervisor
    const { data: operador, error: opError } = await supabase
      .from('usuarios')
      .select('id')
      .eq('id', operadorId)
      .eq('supervisor_id', req.user.userId)
      .single();

    if (!operador || opError) {
      return res.status(404).json({ error: 'Operador não encontrado' });
    }

    // Atualiza ou cria registro
    const { error } = await supabase
      .from('monitoramento')
      .upsert(
        { operador_id: operadorId, status_online },
        { onConflict: 'operador_id' }
      );

    if (error) throw error;

    res.status(200).json({ 
      message: 'Status atualizado',
      operador_id: operadorId,
      status: status_online
    });

  } catch (error) {
    console.error('Erro ao atualizar status:', error);
    res.status(500).json({ error: 'Erro ao atualizar status' });
  }
});

// =============================================
// Health Check e Inicialização
// =============================================

/**
 * @swagger
 * /health:
 *   get:
 *     tags: [Health Check]
 *     summary: Verifica status da API
 *     responses:
 *       200:
 *         description: API online
 */
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Error Handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Erro interno',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
  console.log(`Documentação: http://localhost:${PORT}/docs`);
});
