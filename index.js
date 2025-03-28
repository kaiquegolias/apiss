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

// Configuração básica do Express
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Configuração de sessão com PostgreSQL para produção
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
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 dias
    }
  })
);

// Middleware para verificar conexão com o banco de dados
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

// Middleware para verificar autenticação
const verificarAutenticacao = (req, res, next) => {
  if (!req.session.token) {
    return res.status(401).json({ error: 'Usuário não autenticado' });
  }

  try {
    const decoded = jwt.verify(req.session.token, process.env.JWT_SECRET || 'dev-secret-fallback');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
};

// Middleware para verificar supervisor
const verificarSupervisor = (req, res, next) => {
  if (req.user.nivel_acesso !== 'supervisor') {
    return res.status(403).json({ 
      error: 'Acesso negado. Somente supervisores podem acessar esta rota.' 
    });
  }
  next();
};

// Configuração do Swagger
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API de Monitoramento',
      version: '1.0.0',
      description: 'API para monitoramento de operadores e batidas de ponto',
    },
    servers: [
      {
        url: process.env.RENDER_EXTERNAL_URL || `http://localhost:${process.env.PORT || 3000}`,
        description: process.env.NODE_ENV === 'production' ? 'Servidor de produção' : 'Servidor local'
      }
    ],
    components: {
      securitySchemes: {
        cookieAuth: {
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

// Middleware para expor a especificação Swagger JSON
app.get('/docs-json', (req, res) => {
  res.json(swaggerDocs);
});

// Configuração da UI do Swagger
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs, {
  explorer: true,
  customSiteTitle: 'API de Monitoramento - Documentação'
}));

/**
 * @swagger
 * /health:
 *   get:
 *     summary: Verifica o status da API
 *     tags: [Health Check]
 *     responses:
 *       200:
 *         description: API está funcionando
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 database:
 *                   type: string
 *                 environment:
 *                   type: string
 */
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK',
    database: 'Connected',
    environment: process.env.NODE_ENV || 'development'
  });
});

/**
 * @swagger
 * /auth/login-operador:
 *   post:
 *     summary: Login para operadores
 *     tags: [Autenticação]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - senha
 *             properties:
 *               email:
 *                 type: string
 *                 example: operador@empresa.com
 *               senha:
 *                 type: string
 *                 example: senha123
 *     responses:
 *       200:
 *         description: Login bem-sucedido
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 nivel_acesso:
 *                   type: string
 *                 userId:
 *                   type: string
 *       400:
 *         description: Credenciais inválidas
 *       500:
 *         description: Erro interno do servidor
 */
app.post('/auth/login-operador', async (req, res) => {
  try {
    const { email, senha } = req.body;

    const { data: user, error } = await supabase
      .from('usuarios')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(400).json({ error: 'Usuário não encontrado' });
    }

    const senhaCorreta = await bcrypt.compare(senha, user.senha);
    if (!senhaCorreta) {
      return res.status(400).json({ error: 'Senha incorreta' });
    }

    const token = jwt.sign(
      {
        userId: user.id,
        nivel_acesso: user.nivel_acesso,
      },
      process.env.JWT_SECRET || 'dev-secret-fallback',
      { expiresIn: '1h' }
    );

    req.session.token = token;
    res.json({ 
      message: 'Login bem-sucedido', 
      nivel_acesso: user.nivel_acesso,
      userId: user.id
    });

  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

/**
 * @swagger
 * /auth/login-supervisor:
 *   post:
 *     summary: Login para supervisores
 *     tags: [Autenticação]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - senha
 *             properties:
 *               email:
 *                 type: string
 *                 example: supervisor@empresa.com
 *               senha:
 *                 type: string
 *                 example: senha123
 *     responses:
 *       200:
 *         description: Login bem-sucedido
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 nivel_acesso:
 *                   type: string
 *                 userId:
 *                   type: string
 *       400:
 *         description: Credenciais inválidas
 *       403:
 *         description: Acesso permitido apenas para supervisores
 *       500:
 *         description: Erro interno do servidor
 */
app.post('/auth/login-supervisor', async (req, res) => {
  try {
    const { email, senha } = req.body;

    const { data: user, error } = await supabase
      .from('usuarios')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(400).json({ error: 'Usuário não encontrado' });
    }

    if (user.nivel_acesso !== 'supervisor') {
      return res.status(403).json({ error: 'Acesso permitido apenas para supervisores' });
    }

    const senhaCorreta = await bcrypt.compare(senha, user.senha);
    if (!senhaCorreta) {
      return res.status(400).json({ error: 'Senha incorreta' });
    }

    const token = jwt.sign(
      {
        userId: user.id,
        nivel_acesso: user.nivel_acesso,
      },
      process.env.JWT_SECRET || 'dev-secret-fallback',
      { expiresIn: '1h' }
    );

    req.session.token = token;
    res.json({ 
      message: 'Login de supervisor bem-sucedido', 
      nivel_acesso: user.nivel_acesso,
      userId: user.id
    });

  } catch (error) {
    console.error('Erro no login supervisor:', error);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

/**
 * @swagger
 * /operador/list:
 *   get:
 *     summary: Lista operadores associados ao supervisor
 *     tags: [Supervisor]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Lista de operadores
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: string
 *                   nome:
 *                     type: string
 *                   email:
 *                     type: string
 *                   nivel_acesso:
 *                     type: string
 *       401:
 *         description: Não autenticado
 *       403:
 *         description: Acesso negado (não é supervisor)
 *       500:
 *         description: Erro interno do servidor
 */
app.get('/operador/list', verificarAutenticacao, verificarSupervisor, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('usuarios')
      .select('*')
      .eq('supervisor_id', req.user.userId);

    if (error) {
      throw error;
    }

    res.status(200).json(data);
  } catch (error) {
    console.error('Erro ao listar operadores:', error);
    res.status(500).json({ error: 'Erro ao buscar operadores' });
  }
});

/**
 * @swagger
 * /monitoramento/{operadorId}:
 *   get:
 *     summary: Monitora status de um operador
 *     tags: [Supervisor]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: operadorId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID do operador
 *     responses:
 *       200:
 *         description: Dados de monitoramento
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 operador_id:
 *                   type: string
 *                 nome:
 *                   type: string
 *                 status_online:
 *                   type: boolean
 *                 horario_entrada:
 *                   type: string
 *                   nullable: true
 *                 horario_almoco:
 *                   type: string
 *                   nullable: true
 *                 horario_saida:
 *                   type: string
 *                   nullable: true
 *       401:
 *         description: Não autenticado
 *       403:
 *         description: Acesso negado (não é supervisor)
 *       404:
 *         description: Operador não encontrado
 *       500:
 *         description: Erro interno do servidor
 */
app.get('/monitoramento/:operadorId', verificarAutenticacao, verificarSupervisor, async (req, res) => {
  try {
    const { operadorId } = req.params;

    const { data: operador, error: userError } = await supabase
      .from('usuarios')
      .select('id, nome, nivel_acesso')
      .eq('id', operadorId)
      .eq('supervisor_id', req.user.userId)
      .single();

    if (userError || !operador) {
      return res.status(404).json({ 
        error: 'Operador não encontrado ou não está sob sua supervisão' 
      });
    }

    const { data: monitoramento, error: monitoramentoError } = await supabase
      .from('monitoramento')
      .select('status_online, horario_entrada, horario_almoco, horario_saida')
      .eq('operador_id', operadorId)
      .single();

    if (monitoramentoError || !monitoramento) {
      return res.status(200).json({
        operador_id: operador.id,
        nome: operador.nome,
        status_online: false,
        horario_entrada: null,
        horario_almoco: null,
        horario_saida: null,
        mensagem: 'Dados de monitoramento não encontrados, assumindo status offline'
      });
    }

    res.status(200).json({
      operador_id: operador.id,
      nome: operador.nome,
      ...monitoramento
    });

  } catch (error) {
    console.error('Erro no monitoramento:', error);
    res.status(500).json({ error: 'Erro ao buscar dados de monitoramento' });
  }
});

/**
 * @swagger
 * /monitoramento/{operadorId}/status:
 *   put:
 *     summary: Atualiza status de um operador
 *     tags: [Supervisor]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: operadorId
 *         required: true
 *         schema:
 *           type: string
 *         description: ID do operador
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - status_online
 *             properties:
 *               status_online:
 *                 type: boolean
 *                 description: Novo status do operador
 *     responses:
 *       200:
 *         description: Status atualizado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 operador_id:
 *                   type: string
 *                 status:
 *                   type: boolean
 *       401:
 *         description: Não autenticado
 *       403:
 *         description: Acesso negado (não é supervisor)
 *       404:
 *         description: Operador não encontrado
 *       500:
 *         description: Erro interno do servidor
 */
app.put('/monitoramento/:operadorId/status', verificarAutenticacao, verificarSupervisor, async (req, res) => {
  try {
    const { operadorId } = req.params;
    const { status_online } = req.body;

    const { data: operador, error: userError } = await supabase
      .from('usuarios')
      .select('id')
      .eq('id', operadorId)
      .eq('supervisor_id', req.user.userId)
      .single();

    if (userError || !operador) {
      return res.status(404).json({ 
        error: 'Operador não encontrado ou não está sob sua supervisão' 
      });
    }

    const { data: existingRecord } = await supabase
      .from('monitoramento')
      .select('operador_id')
      .eq('operador_id', operadorId)
      .single();

    const { error } = existingRecord 
      ? await supabase
          .from('monitoramento')
          .update({ status_online })
          .eq('operador_id', operadorId)
      : await supabase
          .from('monitoramento')
          .insert({
            operador_id: operadorId,
            status_online,
            horario_entrada: null,
            horario_almoco: null,
            horario_saida: null
          });

    if (error) {
      throw error;
    }

    res.status(200).json({ 
      message: 'Status do operador atualizado com sucesso',
      operador_id: operadorId,
      status: status_online
    });

  } catch (error) {
    console.error('Erro ao atualizar status:', error);
    res.status(500).json({ error: 'Erro ao atualizar status do operador' });
  }
});

// Middleware de erro global
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Erro interno do servidor',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
  console.log(`Ambiente: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Docs disponíveis em: ${process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`}/docs`);
});
