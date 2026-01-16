const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = "ovni_secret";

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // login simple (después va DB)
  if (email === "test@ovni.com" && password === "1234") {
    const token = jwt.sign({ email }, SECRET, { expiresIn: "1d" });
    return res.json({ token });
  }

  return res.status(401).json({ error: "Credenciales inválidas" });
});

app.get("/profile", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(auth.split(" ")[1], SECRET);
    res.json(decoded);
  } catch {
    res.sendStatus(403);
  }
});

app.listen(3001, () =>
  console.log("🔥 OVNI Backend en http://localhost:3001")
);
