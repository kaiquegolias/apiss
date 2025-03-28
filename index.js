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

// ====================== CONFIGURAÇÃO INICIAL ======================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Configuração de sessão com PostgreSQL
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
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: 'lax'
    }
  })
);

// ====================== MIDDLEWARES ======================
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

// ====================== SWAGGER ======================
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API de Monitoramento Completo',
      version: '1.0.0',
      description: 'API para gestão completa de operadores e supervisores'
    },
    servers: [{ url: process.env.RENDER_EXTERNAL_URL || `http://localhost:${process.env.PORT || 3000}` }],
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
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// ====================== ROTAS DE AUTENTICAÇÃO ======================
/**
 * @swagger
 * /auth/login-operador:
 *   post:
 *     tags: [Autenticação]
 *     summary: Login para operadores
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
    console.error('Erro no login supervisor:', error);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// ====================== ROTAS DE OPERADOR ======================
/**
 * @swagger
 * /operador/cadastrar:
 *   post:
 *     tags: [Supervisor]
 *     summary: Cadastra novo operador
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
      .insert({ 
        operador_id: novoOperador.id,
        status_online: false
      });

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
        monitoramento(
          status_online
        )
      `)
      .eq('supervisor_id', req.user.userId);

    if (error) throw error;

    // Formata resposta incluindo status_online
    const resposta = operadores.map(op => ({
      id: op.id,
      nome: op.nome,
      email: op.email,
      nivel_acesso: op.nivel_acesso,
      online: op.monitoramento?.status_online || false
    }));

    res.status(200).json(resposta);
  } catch (error) {
    console.error('Erro ao listar operadores:', error);
    res.status(500).json({ error: 'Erro ao buscar operadores' });
  }
});

// ====================== ROTAS DE MONITORAMENTO ======================
/**
 * @swagger
 * /monitoramento/registrar:
 *   post:
 *     tags: [Operador]
 *     summary: Registra evento de monitoramento
 */
app.post('/monitoramento/registrar', verificarAutenticacao, async (req, res) => {
  try {
    const { tipo } = req.body;
    const agora = new Date().toISOString();
    let updateData = { 
      operador_id: req.user.userId,
      ultima_atividade: agora 
    };

    switch (tipo) {
      case 'entrada':
        updateData.horario_entrada = agora;
        updateData.status_online = true;
        break;
      case 'saida':
        updateData.horario_saida = agora;
        updateData.status_online = false;
        break;
      case 'almoco_inicio':
        updateData.horario_almoco_inicio = agora;
        break;
      case 'almoco_fim':
        updateData.horario_almoco_fim = agora;
        break;
      case 'ping':
        updateData.status_online = true;
        break;
      default:
        return res.status(400).json({ error: 'Tipo de evento inválido' });
    }

    const { error } = await supabase
      .from('monitoramento')
      .upsert(updateData, { onConflict: 'operador_id' });

    if (error) throw error;

    res.status(200).json({ 
      message: `Evento ${tipo} registrado`,
      horario: agora,
      status: updateData.status_online
    });
  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ error: 'Erro ao registrar evento' });
  }
});

/**
 * @swagger
 * /monitoramento/status:
 *   get:
 *     tags: [Supervisor]
 *     summary: Retorna status completo dos operadores
 */
app.get('/monitoramento/status', verificarAutenticacao, verificarSupervisor, async (req, res) => {
  try {
    const { data: operadores, error } = await supabase
      .from('usuarios')
      .select(`
        id,
        nome,
        email,
        monitoramento(
          status_online,
          horario_entrada,
          horario_almoco_inicio,
          horario_almoco_fim,
          horario_saida,
          ultima_atividade
        )
      `)
      .eq('supervisor_id', req.user.userId);

    if (error) throw error;

    const resposta = operadores.map(op => ({
      id: op.id,
      nome: op.nome,
      email: op.email,
      online: op.monitoramento?.status_online || false,
      horarios: {
        entrada: op.monitoramento?.horario_entrada || null,
        almoco: {
          inicio: op.monitoramento?.horario_almoco_inicio || null,
          fim: op.monitoramento?.horario_almoco_fim || null
        },
        saida: op.monitoramento?.horario_saida || null
      },
      ultima_atividade: op.monitoramento?.ultima_atividade || null
    }));

    res.status(200).json(resposta);
  } catch (error) {
    console.error('Erro ao buscar status:', error);
    res.status(500).json({ error: 'Erro ao buscar dados de monitoramento' });
  }
});

// ====================== ROTAS ORIGINAIS DE MONITORAMENTO ======================
/**
 * @swagger
 * /monitoramento/{operadorId}:
 *   get:
 *     tags: [Supervisor]
 *     summary: Verifica status de um operador
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
      status: monitoramento || { 
        status_online: false,
        horario_entrada: null,
        horario_almoco_inicio: null,
        horario_almoco_fim: null,
        horario_saida: null
      }
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

    // Atualiza status
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

// ====================== HEALTH CHECK ======================
/**
 * @swagger
 * /health:
 *   get:
 *     tags: [Health Check]
 *     summary: Verifica status da API
 */
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  });
});

// ====================== INICIALIZAÇÃO ======================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
  console.log(`Documentação: http://localhost:${PORT}/docs`);
});
