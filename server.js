// server.js
require("dotenv").config();
const path = require("path");
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const mongoose = require("mongoose");
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
  max: 100, // 100 requêtes / minute par IP
  standardHeaders: true,
  legacyHeaders: false
});

app.use(apiLimiter);
app.use(express.json());
app.use(cookieParser());

// ----- Static -----
app.use(express.static(__dirname));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ----- MongoDB -----
mongoose.connect(process.env.MONGODB_URI, { autoIndex: true })
  .then(() => console.log("✅ MongoDB connecté"))
  .catch(err => console.error("MongoDB error:", err));

// ----- Modèles -----
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, index: true },
  email:    { type: String },
  passwordHash: { type: String, required: true },
  filiere:  { type: String, enum: ["CS", "SEMI", "RT", null], default: null },
  niveau:   { type: String, enum: ["L1","L2","L3","M1","M2", null], default: null },
  createdAt:{ type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  room:     { type: String, index: true },
  user:     { type: String },
  text:     { type: String },
  type:     { type: String, enum: ["text","image","file"], default: "text" },
  fileUrl:  { type: String, default: null },
  fileName: { type: String, default: null },
  reactions:{ type: Map, of: Number, default: {} }, // e.g. { "👍": 3 }
  createdAt:{ type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Message = mongoose.model("Message", messageSchema);

// ----- Auth helpers -----
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

function signToken(user) {
  return jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: "30d" });
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

// ----- Routes Auth -----
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, filiere, niveau } = req.body;
    if (!username || !password) return res.status(400).json({ error: "username et password requis" });
    const exists = await User.findOne({ username });
    if (exists) return res.status(409).json({ error: "Ce pseudo existe déjà" });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ username, email, passwordHash, filiere: filiere || null, niveau: niveau || null });

    const token = signToken(user);
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", secure: true, maxAge: 1000*60*60*24*30 });
    res.json({ ok: true, username: user.username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: "Identifiants invalides" });
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: "Identifiants invalides" });

    const token = signToken(user);
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", secure: true, maxAge: 1000*60*60*24*30 });
    res.json({ ok: true, username: user.username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get("/api/me", authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id).lean();
  if (!user) return res.status(404).json({ error: "Not found" });
  res.json({ username: user.username, filiere: user.filiere, niveau: user.niveau });
});

// ----- Upload fichiers (images/PDF) -----
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

app.post("/api/upload", authMiddleware, upload.single("file"), async (req, res) => {
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

// ----- Socket.IO avec JWT depuis cookie -----
const onlineUsers = new Map(); // socket.id -> username
const lastMessageTime = new Map(); // anti-spam

io.use((socket, next) => {
  // Récupérer le token depuis les cookies de l’upgrade request
  try {
    const cookie = socket.request.headers.cookie || "";
    const match = cookie.split(";").map(s => s.trim()).find(s => s.startsWith("token="));
    if (!match) return next(); // autorise lecture publique (avant login)
    const token = match.split("=")[1];
    const payload = jwt.verify(token, JWT_SECRET);
    socket.user = { id: payload.id, username: payload.username };
    next();
  } catch (e) {
    // pas bloquant pour rejoindre la page avant login
    next();
  }
});

io.on("connection", (socket) => {
  // présence
  if (socket.user?.username) {
    onlineUsers.set(socket.id, socket.user.username);
  }

  socket.on("joinRoom", async ({ username, room }) => {
    socket.join(room);
    socket.currentRoom = room;

    // Charger les 50 derniers messages du salon
    const history = await Message.find({ room }).sort({ createdAt: -1 }).limit(50).lean();
    socket.emit("history", history.reverse());

    socket.to(room).emit("notification", `${xss(username)} a rejoint le salon`);
    broadcastUserList(room);
  });

  socket.on("message", async (data) => {
    // anti-spam 2s
    const now = Date.now();
    const last = lastMessageTime.get(socket.id) || 0;
    if (now - last < 2000) {
      socket.emit("notification", "⏳ Tu envoies des messages trop vite !");
      return;
    }
    lastMessageTime.set(socket.id, now);

    const cleanText = data.text ? xss(data.text) : "";
    const type = data.type || "text";
    const fileUrl = data.fileUrl || null;
    const fileName = data.fileName || null;

    const doc = await Message.create({
      room: data.room,
      user: data.user,
      text: cleanText,
      type,
      fileUrl,
      fileName
    });

    io.to(data.room).emit("message", {
      _id: doc._id,
      room: doc.room,
      user: doc.user,
      text: doc.text,
      type: doc.type,
      fileUrl: doc.fileUrl,
      fileName: doc.fileName,
      reactions: {},
      createdAt: doc.createdAt
    });
  });

  socket.on("react", async ({ messageId, emoji, room }) => {
    try {
      const msg = await Message.findById(messageId);
      if (!msg) return;
      const current = msg.reactions.get(emoji) || 0;
      msg.reactions.set(emoji, current + 1);
      await msg.save();
      io.to(room).emit("reactionUpdated", { messageId, emoji, count: current + 1 });
    } catch (e) {
      console.error(e);
    }
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
      return s?.user?.username || "Anonyme";
    });
    io.to(room).emit("userList", clients);
  }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log("✅ Serveur lancé sur http://localhost:" + PORT);
});
