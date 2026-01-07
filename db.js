const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./ovni.db");

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      address TEXT,
      privateKey TEXT
    )
  `);
});

module.exports = db;
