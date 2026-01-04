const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("./database");

const app = express();
app.use(cors());
app.use(express.json());

const SECRET_KEY = "tricolor633"; // sua chave secreta

// --- Teste da API ---
app.get("/", (req, res) => {
  res.send("API Corrida rodando 🚀");
});

// --- LOGIN ---
app.post("/login", (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ erro: "Email e senha obrigatórios" });

  db.get("SELECT * FROM usuarios WHERE email = ?", [email], (err, usuario) => {
    if (err) return res.status(500).json({ erro: "Erro no banco de dados" });
    if (!usuario) return res.status(401).json({ erro: "Email ou senha incorretos" });

    if (!bcrypt.compareSync(senha, usuario.senha)) {
      return res.status(401).json({ erro: "Email ou senha incorretos" });
    }

    const token = jwt.sign({ id: usuario.id, email: usuario.email }, SECRET_KEY, { expiresIn: "8h" });
    res.json({ token });
  });
});

// --- MIDDLEWARE DE AUTENTICAÇÃO ---
function autenticarToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ erro: "Não autorizado" });

  jwt.verify(token, SECRET_KEY, (err, usuario) => {
    if (err) return res.status(403).json({ erro: "Token inválido" });
    req.usuario = usuario;
    next();
  });
}

// --- CRIAR INSCRIÇÃO ---
app.post("/inscricoes", (req, res) => {
  let { nome, data_nascimento, cpf, email, telefone, modalidade, sexo, tamanho_camisa, retirada_kit } = req.body;

  if (!nome || !cpf || !email || !modalidade) {
    return res.status(400).json({ erro: "Campos obrigatórios não preenchidos" });
  }

  const cpfLimpo = cpf.replace(/\D/g, '');
  if (!/^\d{11}$/.test(cpfLimpo)) return res.status(400).json({ erro: "CPF inválido" });

  const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
  if (!emailRegex.test(email)) return res.status(400).json({ erro: "Email inválido" });

  const checkSql = `SELECT * FROM inscricoes WHERE cpf = ? OR email = ?`;
  db.get(checkSql, [cpfLimpo, email], (err, existing) => {
    if (err) return res.status(500).json({ erro: "Erro ao verificar CPF/email" });

    if (existing) {
      if (existing.cpf === cpfLimpo) return res.status(400).json({ erro: "Este CPF já foi cadastrado" });
      if (existing.email === email) return res.status(400).json({ erro: "Este email já foi cadastrado" });
    }

    // Pega o último número de inscrição e incrementa
    db.get("SELECT MAX(numero_inscricao) AS maxNum FROM inscricoes", [], (err, row) => {
      if (err) return res.status(500).json({ erro: "Erro ao gerar número de inscrição" });

      const numero_inscricao = row?.maxNum ? row.maxNum + 1 : 1;

      const sql = `
        INSERT INTO inscricoes
        (nome, data_nascimento, cpf, email, telefone, modalidade, sexo, tamanho_camisa, retirada_kit, numero_inscricao)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

      db.run(sql, [nome, data_nascimento, cpfLimpo, email, telefone, modalidade, sexo, tamanho_camisa, retirada_kit, numero_inscricao], function(err) {
        if (err) return res.status(500).json({ erro: "Erro ao salvar inscrição" });

        res.status(201).json({ mensagem: "Inscrição realizada com sucesso!", id: this.lastID });
      });
    });
  });
});

// --- LISTAR INSCRIÇÕES (protegido) ---
app.get("/inscricoes", autenticarToken, (req, res) => {
  db.all("SELECT * FROM inscricoes", [], (err, rows) => {
    if (err) return res.status(500).json({ erro: "Erro ao buscar inscrições" });
    res.json(rows);
  });
});

// --- DELETAR INSCRIÇÃO (protegido) ---
app.delete("/inscricoes/:id", autenticarToken, (req, res) => {
  const { id } = req.params;

  const sql = "DELETE FROM inscricoes WHERE id = ?";
  db.run(sql, [id], function(err) {
    if (err) return res.status(500).json({ erro: "Erro ao apagar inscrição" });
    if (this.changes === 0) return res.status(404).json({ erro: "Inscrição não encontrada" });

    res.json({ mensagem: "Inscrição apagada com sucesso!" });
  });
});

// --- PORTA ---
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});

