const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3001;
const JWT_SECRET = "ovni_super_secret";

// =====================
// MEMORIA
// =====================
const users = {};

// =====================
// AUTH MIDDLEWARE
// =====================
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).send("Token requerido");

  try {
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).send("Token inválido");
  }
}

// =====================
// HEALTH
// =====================
app.get("/", (req, res) => {
  res.send("OVNI backend ONLINE ??");
});

// =====================
// REGISTER
// =====================
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send("Datos incompletos");
  if (users[email]) return res.status(400).send("Usuario ya existe");

  const hash = await bcrypt.hash(password, 10);

  users[email] = {
    email,
    password: hash,
    balance: 0
  };

  res.json({ ok: true });
});

// =====================
// LOGIN
// =====================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users[email];
  if (!user) return res.status(401).send("Credenciales inválidas");

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).send("Credenciales inválidas");

  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" });

  res.json({
    ok: true,
    token,
    wallet: {
      email,
      balance: user.balance
    }
  });
});

// =====================
// BALANCE
// =====================
app.get("/balance", auth, (req, res) => {
  res.json({ balance: users[req.user.email].balance });
});

// =====================
// ADMIN CREDIT
// =====================
app.post("/admin/credit", auth, (req, res) => {
  const { amount } = req.body;
  const email = req.user.email;

  if (!amount || amount <= 0) {
    return res.status(400).send("Monto inválido");
  }

  if (!users[email]) {
    return res.status(404).send("Usuario no existe");
  }

  users[email].balance += Number(amount);

  res.json({
    ok: true,
    balance: users[email].balance
  });
});

// =====================
// TRANSFER
// =====================
app.post("/transfer", auth, (req, res) => {
  const { to, amount } = req.body;
  const from = req.user.email;

  if (!users[to]) return res.status(404).send("Destino no existe");
  if (users[from].balance < amount) return res.status(400).send("Saldo insuficiente");

  users[from].balance -= amount;
  users[to].balance += amount;

  res.json({ ok: true });
});

// =====================
// START
// =====================
app.listen(PORT, () => {
  console.log("OVNI backend ONLINE ??");
});
