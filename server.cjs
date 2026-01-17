require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const twilio = require("twilio");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;

/* =====================
   MEMORIA (TEMPORAL)
===================== */
const users = {};
const otps = {};

/* =====================
   EMAIL OTP
===================== */
const emailTransporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

/* =====================
   SMS OTP (TWILIO)
===================== */
const twilioClient = twilio(
  process.env.TWILIO_SID,
  process.env.TWILIO_TOKEN
);

/* =====================
   HELPERS
===================== */
function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).send("Token requerido");

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).send("Token inválido");
  }
}

/* =====================
   AUTH
===================== */

// REGISTRO
app.post("/auth/register", async (req, res) => {
  const { email, phone, password } = req.body;
  if (!email || !password) {
    return res.status(400).send("Datos incompletos");
  }

  if (users[email]) {
    return res.status(409).send("Usuario ya existe");
  }

  users[email] = {
    email,
    phone,
    password: await bcrypt.hash(password, 10),
    verified: false,
    balance: 0, history: []
  };

  const otp = generateOTP();
  otps[email] = otp;

  await emailTransporter.sendMail({
    from: "OVNI Wallet",
    to: email,
    subject: "Código de verificación OVNI",
    text: `Tu código es: ${otp}`
  });

  if (phone) {
    await twilioClient.messages.create({
      body: `OVNI Wallet código: ${otp}`,
      from: process.env.TWILIO_PHONE,
      to: phone
    });
  }

  res.json({ ok: true, message: "OTP enviado" });
});

// VERIFICAR OTP
app.post("/auth/verify", (req, res) => {
  const { email, otp } = req.body;

  if (otps[email] !== otp) {
    return res.status(401).send("OTP incorrecto");
  }

  users[email].verified = true;
  delete otps[email];

  const token = jwt.sign(
    { email },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ ok: true, token });
});

// LOGIN
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users[email];

  if (!user) return res.status(404).send("Usuario no existe");
  if (!user.verified) return res.status(401).send("Usuario no verificado");

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).send("Password incorrecta");

  const token = jwt.sign(
    { email },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ ok: true, token });
});

/* =====================
   WALLET
===================== */

// INFO WALLET
app.get("/wallet", auth, (req, res) => {
  const user = users[req.user.email];
  res.json({
    email: user.email,
    balance: user.balance,
    currency: "OVNI"
  });
});

// TRANSFERENCIA
app.post("/wallet/transfer", auth, (req, res) => {
  const { to, amount } = req.body;
  const fromUser = users[req.user.email];
  const toUser = users[to];

  if (!toUser) return res.status(404).send("Destino no existe");
  if (amount <= 0) return res.status(400).send("Monto inválido");
  if (fromUser.balance < amount) return res.status(400).send("Saldo insuficiente");

  fromUser.balance -= amount;
  toUser.balance += amount;

  fromUser.history = fromUser.history || [];
  toUser.history = toUser.history || [];

  const tx = {
    type: "send",
    to,
    amount,
    date: new Date()
  };

  fromUser.history.push(tx);
  toUser.history.push({
    type: "receive",
    from: req.user.email,
    amount,
    date: new Date()
  });

  res.json({ ok: true, balance: fromUser.balance });
});

// HISTORIAL
app.get("/wallet/history", auth, (req, res) => {
  const user = users[req.user.email];
  res.json(user.history || []);
});

/* =====================
   START
===================== */
app.get("/wallet", auth, (req, res) => {
  const user = users[req.user.email];

  if (!user) {
    return res.status(404).send("Usuario no encontrado");
  }

  res.json({
    email: req.user.email,
    balance: user.balance
  });
});

app.listen(PORT, () => {
  console.log(`OVNI Backend corriendo en puerto ${PORT}`);
});



