// server.js
require("dotenv").config();
const path = require("path");
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const xss = require("xss");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: true, credentials: true }
});

// ----- Sécurité API : rate limit -----
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

app.use(apiLimiter);
app.use(express.json());
app.use(cookieParser());

// ----- Static -----
app.use(express.static(__dirname));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ----- Auth helpers -----
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
}

function authMiddleware(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: "Unauthenticated" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ----- Routes simplifiées -----
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "username et password requis" });

    // ⚠️ Pas de base de données → utilisateur fictif
    const fakeUser = { id: "1", username, passwordHash: await bcrypt.hash(password, 10) };

    const token = signToken(fakeUser);
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", secure: true, maxAge: 1000 * 60 * 60 * 24 * 30 });
    res.json({ ok: true, username: fakeUser.username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    // ⚠️ Ici tu devras mettre un vrai check si tu réactives MongoDB
    const fakeUser = { id: "1", username, passwordHash: await bcrypt.hash(password, 10) };

    const match = await bcrypt.compare(password, fakeUser.passwordHash);
    if (!match) return res.status(401).json({ error: "Identifiants invalides" });

    const token = signToken(fakeUser);
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", secure: true, maxAge: 1000 * 60 * 60 * 24 * 30 });
    res.json({ ok: true, username: fakeUser.username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get("/api/me", authMiddleware, async (req, res) => {
  res.json({ username: req.user.username });
});

// ----- Upload fichiers -----
const MAX_MB = parseInt(process.env.MAX_UPLOAD_MB || "10", 10);
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, path.join(__dirname, "uploads")),
  filename: (_req, file, cb) => {
    const id = uuidv4();
    const ext = path.extname(file.originalname);
    cb(null, `${id}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_MB * 1024 * 1024 }
});

app.post("/api/upload", authMiddleware, upload.single("file"), (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ error: "Aucun fichier" });

    const url = `/uploads/${file.filename}`;
    res.json({ url, name: file.originalname });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erreur upload" });
  }
});

// ----- Servir index.html -----
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ----- Socket.IO -----
const onlineUsers = new Map();
const lastMessageTime = new Map();

io.on("connection", (socket) => {
  console.log("Nouvelle connexion socket:", socket.id);

  socket.on("joinRoom", ({ username, room }) => {
    socket.join(room);
    socket.currentRoom = room;
    socket.to(room).emit("notification", `${xss(username)} a rejoint le salon`);
    broadcastUserList(room);
  });

  socket.on("message", (data) => {
    const now = Date.now();
    const last = lastMessageTime.get(socket.id) || 0;
    if (now - last < 2000) {
      socket.emit("notification", "⏳ Tu envoies des messages trop vite !");
      return;
    }
    lastMessageTime.set(socket.id, now);

    io.to(data.room).emit("message", {
      user: data.user,
      text: xss(data.text),
      createdAt: new Date()
    });
  });

  socket.on("disconnect", () => {
    const username = onlineUsers.get(socket.id);
    const room = socket.currentRoom;
    onlineUsers.delete(socket.id);
    if (username && room) {
      socket.to(room).emit("notification", `${xss(username)} a quitté`);
      broadcastUserList(room);
    }
  });

  function broadcastUserList(room) {
    const clients = Array.from(io.sockets.adapter.rooms.get(room) || []).map(id => {
      const s = io.sockets.sockets.get(id);
      return s?.username || "Anonyme";
    });
    io.to(room).emit("userList", clients);
  }
});

// ----- Lancement du serveur -----
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log("✅ Serveur lancé sur http://localhost:" + PORT);
});
