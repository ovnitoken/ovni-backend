const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");

const app = express();

/* 🔑 MIDDLEWARES (ESTO ERA EL PROBLEMA) */
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;
const JWT_SECRET = "ovni_secret_key";

/* 🧠 USUARIOS EN MEMORIA */
const users = [];

/* =====================
   HEALTH CHECK
===================== */
app.get("/", (req, res) => {
  res.send("OVNI backend ONLINE 🚀");
});

/* =====================
   REGISTER
===================== */
app.post("/register", async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).send("Datos incompletos");
  }

  const exists = users.find(u => u.email === email);
  if (exists) {
    return res.status(409).send("Usuario ya existe");
  }

  const hash = await bcrypt.hash(password, 10);
  users.push({ email, password: hash, balance: 0 });

  res.json({ ok: true, message: "Usuario registrado" });
});

/* =====================
   LOGIN
===================== */
app.post("/login", async (req, res) => {
  const { email, password } = req.body || {};

  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(401).send("Credenciales inválidas");
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(401).send("Credenciales inválidas");
  }

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

/* =====================
   START
===================== */
app.listen(PORT, () => {
  console.log("Servidor escuchando en puerto", PORT);
});
/* =====================
   AUTH MIDDLEWARE
===================== */
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).send("Token requerido");

  const token = header.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).send("Token inválido");
  }
}
/* =====================
   BALANCE
===================== */
app.get("/balance", auth, (req, res) => {
  const user = users.find(u => u.email === req.user.email);
  res.json({ balance: user.balance });
});
/* =====================
   TRANSFER
===================== */
app.post("/transfer", auth, (req, res) => {
  const { to, amount } = req.body;

  if (!to || !amount || amount <= 0) {
    return res.status(400).send("Datos inválidos");
  }

  const fromUser = users.find(u => u.email === req.user.email);
  const toUser = users.find(u => u.email === to);

  if (!toUser) return res.status(404).send("Destino no existe");
  if (fromUser.balance < amount) return res.status(400).send("Saldo insuficiente");

  fromUser.balance -= amount;
  toUser.balance += amount;

  res.json({
    ok: true,
    from: fromUser.email,
    to,
    amount
  });
});
