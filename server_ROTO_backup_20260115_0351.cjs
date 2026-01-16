require('dotenv').config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = "OVNI_SUPER_SECRET";

app.get("/", (req, res) => {
  res.send("OVNI Wallet Backend OK");
});

app.listen(3001, () => {
  console.log("?? Backend OVNI corriendo en puerto 3001");
});

const users = {};
const otps = {};

const nodemailer = require("nodemailer");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const twilio = require("twilio");

const emailTransporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const twilioClient = twilio(
  process.env.TWILIO_SID,
  process.env.TWILIO_TOKEN
);

// GENERAR OTP
function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

// REGISTRO
app.post("/auth/register", async (req, res) => {
  const { email, phone, password } = req.body;
  if (!email || !password) return res.status(400).send("Datos incompletos");

  users[email] = {
    email,
    phone,
    password: await bcrypt.hash(password, 10),
    verified: false,
    balance: 0
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
  if (!user.verified) return res.status(401).send("No verificado");

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).send("Password incorrecta");

  const token = jwt.sign(
    { email },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ ok: true, token });
});
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
