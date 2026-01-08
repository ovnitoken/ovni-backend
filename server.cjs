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
