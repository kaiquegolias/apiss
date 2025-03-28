import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import expressSession from 'express-session';
import swaggerUi from 'swagger-ui-express';
import swaggerJsDoc from 'swagger-jsdoc';
import { supabase } from './supabase.js'

const app = express();
app.use(express.json());
app.use(cookieParser());

app.use(
  expressSession({
    secret: process.env.SESSION_SECRET || 'fallback-secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' } // HTTPS em produção
  })
)

// Verificar conexão com o banco de dados
(async () => {
  const { data, error } = await supabase.from('usuarios').select('*').limit(1);
  if (error) {
    console.error('Erro ao conectar ao banco de dados:', error.message);
  } else {
    console.log('Banco de dados conectado com sucesso!');
  }
})();

// Middleware para verificar se o usuário está autenticado
const verificarAutenticacao = (req, res, next) => {
  if (!req.session.token) {
    return res.status(401).json({ error: 'Usuário não autenticado' });
  }

  try {
    const decoded = jwt.verify(req.session.token, 'seu-segredo-jwt');
    req.user = decoded; // Passar o usuário para as rotas
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
};

// Middleware para verificar se o usuário é supervisor
const verificarSupervisor = (req, res, next) => {
  if (req.user.nivel_acesso !== 'supervisor') {
    return res.status(403).json({ error: 'Acesso negado. Somente supervisores podem acessar esta rota.' });
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
  },
  apis: ['index.js'],
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

/**
 * @swagger
 * /auth/login-operador:
 *   post:
 *     tags: [Operador]
 *     summary: Realiza login do operador e cria uma sessão
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
 *       400:
 *         description: Credenciais inválidas
 */
app.post('/auth/login-operador', async (req, res) => {
  const { email, senha } = req.body;

  const { data: user, error } = await supabase
    .from('usuarios')
    .select('*')
    .eq('email', email)
    .single();

  if (error || !user) return res.status(400).json({ error: 'Usuário não encontrado' });

  const senhaCorreta = await bcrypt.compare(senha, user.senha);
  if (!senhaCorreta) return res.status(400).json({ error: 'Senha incorreta' });

  // Gerando o token JWT
  const token = jwt.sign(
    {
      userId: user.id,
      nivel_acesso: user.nivel_acesso,
    },
    'seu-segredo-jwt',
    { expiresIn: '1h' }
  );

  // Armazenar o token na sessão
  req.session.token = token;

  res.json({ message: 'Login bem-sucedido', nivel_acesso: user.nivel_acesso });
});

/**
 * @swagger
 * /auth/login-supervisor:
 *   post:
 *     tags: [Supervisor]
 *     summary: Realiza login do supervisor e cria uma sessão
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
 *       400:
 *         description: Credenciais inválidas
 */
app.post('/auth/login-supervisor', async (req, res) => {
  const { email, senha } = req.body;

  const { data: user, error } = await supabase
    .from('usuarios')
    .select('*')
    .eq('email', email)
    .single();

  if (error || !user) return res.status(400).json({ error: 'Usuário não encontrado' });

  const senhaCorreta = await bcrypt.compare(senha, user.senha);
  if (!senhaCorreta) return res.status(400).json({ error: 'Senha incorreta' });

  // Gerando o token JWT
  const token = jwt.sign(
    {
      userId: user.id,
      nivel_acesso: user.nivel_acesso,
    },
    'seu-segredo-jwt',
    { expiresIn: '1h' }
  );

  // Armazenar o token na sessão
  req.session.token = token;

  res.json({ message: 'Login de supervisor bem-sucedido', nivel_acesso: user.nivel_acesso });
});

/**
 * @swagger
 * /operador/list:
 *   get:
 *     tags: [Supervisor]
 *     summary: Lista os operadores associados ao supervisor logado
 *     responses:
 *       200:
 *         description: Lista de operadores
 *       401:
 *         description: Usuário não autenticado
 */
app.get('/operador/list', verificarAutenticacao, verificarSupervisor, async (req, res) => {
  const { data, error } = await supabase
    .from('usuarios')
    .select('*')
    .eq('supervisor_id', req.user.userId);

  if (error) return res.status(400).json({ error: error.message });

  res.status(200).json(data);
});

/**
 * @swagger
 * /monitoramento/{operadorId}:
 *   get:
 *     tags: [Supervisor]
 *     summary: Verifica o status de um operador
 *     parameters:
 *       - in: path
 *         name: operadorId
 *         required: true
 *         description: ID do operador para monitoramento
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Dados do operador e status de monitoramento
 *       404:
 *         description: Operador não encontrado
 */
app.get('/monitoramento/:operadorId', verificarAutenticacao, verificarSupervisor, async (req, res) => {
  const { operadorId } = req.params;

  // Verificar se o operador existe na tabela usuarios e é subordinado ao supervisor
  const { data: operador, error: userError } = await supabase
    .from('usuarios')
    .select('id, nome, nivel_acesso')
    .eq('id', operadorId)
    .eq('supervisor_id', req.user.userId)
    .single();

  if (userError || !operador) {
    return res.status(404).json({ error: 'Operador não encontrado ou não está sob sua supervisão' });
  }

  // Buscar dados de monitoramento
  const { data: monitoramento, error: monitoramentoError } = await supabase
    .from('monitoramento')
    .select('status_online, horario_entrada, horario_almoco, horario_saida')
    .eq('operador_id', operadorId)
    .single();

  // Se não encontrar na tabela monitoramento, retornar dados básicos com status offline
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
});

/**
 * @swagger
 * /monitoramento/{operadorId}/status:
 *   put:
 *     tags: [Supervisor]
 *     summary: Atualiza o status de um operador (online ou offline)
 *     parameters:
 *       - in: path
 *         name: operadorId
 *         required: true
 *         description: ID do operador para atualizar status
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
 *                 description: Status de online (true para online, false para offline)
 *     responses:
 *       200:
 *         description: Status atualizado com sucesso
 *       404:
 *         description: Operador não encontrado
 */
app.put('/monitoramento/:operadorId/status', verificarAutenticacao, verificarSupervisor, async (req, res) => {
  const { operadorId } = req.params;
  const { status_online } = req.body;

  // Primeiro verificar se o operador existe e está sob supervisão do usuário atual
  const { data: operador, error: userError } = await supabase
    .from('usuarios')
    .select('id')
    .eq('id', operadorId)
    .eq('supervisor_id', req.user.userId)
    .single();

  if (userError || !operador) {
    return res.status(404).json({ error: 'Operador não encontrado ou não está sob sua supervisão' });
  }

  // Verificar se já existe um registro de monitoramento
  const { data: existingRecord, error: checkError } = await supabase
    .from('monitoramento')
    .select('operador_id')
    .eq('operador_id', operadorId)
    .single();

  let result;
  if (checkError || !existingRecord) {
    // Se não existir, criar um novo registro
    result = await supabase
      .from('monitoramento')
      .insert({
        operador_id: operadorId,
        status_online,
        horario_entrada: null,
        horario_almoco: null,
        horario_saida: null
      });
  } else {
    // Se existir, atualizar
    result = await supabase
      .from('monitoramento')
      .update({ status_online })
      .eq('operador_id', operadorId);
  }

  if (result.error) {
    return res.status(400).json({ error: result.error.message });
  }

  res.status(200).json({ message: 'Status do operador atualizado com sucesso' });
});

// Iniciar servidor
const PORT = 3000;
app.listen(PORT, () => console.log(`Servidor rodando em http://localhost:${PORT}`));
