const express = require("express");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const QRCode = require("qrcode");

const app = express();
app.use(express.json());

const PORT = 3001;
const SECRET = "OVNI_SECRET_KEY";

const usersDir = path.join(__dirname, "users");
const usersFile = path.join(usersDir, "users.json");
const txFile = path.join(usersDir, "tx.json");

if (!fs.existsSync(usersDir)) fs.mkdirSync(usersDir);
if (!fs.existsSync(usersFile)) fs.writeFileSync(usersFile, "{}");
if (!fs.existsSync(txFile)) fs.writeFileSync(txFile, "[]");

const readUsers = () => JSON.parse(fs.readFileSync(usersFile));
const saveUsers = (data) => fs.writeFileSync(usersFile, JSON.stringify(data, null, 2));
const readTx = () => JSON.parse(fs.readFileSync(txFile));
const saveTx = (data) => fs.writeFileSync(txFile, JSON.stringify(data, null, 2));

app.post("/register", async (req, res) => {
  const { user, pass } = req.body;
  if (!user || !pass) return res.status(400).send("Datos incompletos");

  const users = readUsers();
  if (users[user]) return res.status(400).send("Usuario existe");

  const hash = await bcrypt.hash(pass, 10);

  users[user] = {
    pass: hash,
    balance: 1000
  };

  saveUsers(users);
  res.send("Usuario creado");
});

app.post("/login", async (req, res) => {
  const { user, pass } = req.body;
  const users = readUsers();

  if (!users[user]) return res.status(401).send("No existe");

  const ok = await bcrypt.compare(pass, users[user].pass);
  if (!ok) return res.status(401).send("Clave incorrecta");

  const token = jwt.sign({ user }, SECRET, { expiresIn: "1h" });
  res.json({ token });
});

const auth = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.sendStatus(401);
  try {
    req.user = jwt.verify(token, SECRET).user;
    next();
  } catch {
    res.sendStatus(403);
  }
};

app.get("/balance", auth, (req, res) => {
  const users = readUsers();
  res.json({ balance: users[req.user].balance });
});

app.post("/transfer", auth, (req, res) => {
  const { to, amount } = req.body;
  const users = readUsers();
  const tx = readTx();

  if (!users[to]) return res.status(400).send("Destino inv�lido");
  if (users[req.user].balance < amount) return res.status(400).send("Saldo insuficiente");

  users[req.user].balance -= amount;
  users[to].balance += amount;

  tx.push({
    from: req.user,
    to,
    amount,
    date: new Date().toISOString()
  });

  saveUsers(users);
  saveTx(tx);
  res.send("Transferencia OK");
});

app.get("/tx", auth, (req, res) => {
  const tx = readTx().filter(t => t.from === req.user || t.to === req.user);
  res.json(tx);
});

app.get("/qr", auth, async (req, res) => {
  const qr = await QRCode.toDataURL(`OVNI:${req.user}`);
  res.json({ qr });
});

app.listen(PORT, () => {
  console.log(`?? OVNI Backend listo en http://localhost:${PORT}`);
});

app.get("/", (req, res) => {
  res.send("OVNI backend ONLINE 🚀");
});
