// server.js
require("dotenv").config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const http = require("http");
const cors = require("cors");
const helmet = require("helmet");
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
  cors: {
    origin: process.env.CLIENT_ORIGIN || true,
    credentials: true
  }
});

// ----- Security middlewares -----
app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

// ----- Rate limiter -----
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(apiLimiter);

// ----- CORS -----
if (process.env.CLIENT_ORIGIN) {
  app.use(cors({ origin: process.env.CLIENT_ORIGIN, credentials: true }));
} else {
  app.use(cors({ origin: true, credentials: true }));
}

// ----- Static files -----
app.use(express.static(__dirname));
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use("/uploads", express.static(uploadsDir));

// ----- MongoDB -----
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/chatdb";
mongoose.connect(MONGODB_URI, { autoIndex: true })
  .then(() => console.log("✅ MongoDB connecté"))
  .catch(err => console.error("MongoDB error:", err));

// ----- Schemas -----
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, index: true },
  email: { type: String },
  passwordHash: { type: String, required: true },
  filiere: { type: String, enum: ["CS", "SEMI", "RT", null], default: null },
  niveau: { type: String, enum: ["L1", "L2", "L3", "M1", "M2", null], default: null },
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  room: { type: String, index: true },
  user: { type: String },
  text: { type: String },
  type: { type: String, enum: ["text", "image", "file"], default: "text" },
  fileUrl: { type: String, default: null },
  fileName: { type: String, default: null },
  reactions: { type: Map, of: Number, default: {} },
  createdAt: { type: Date, default: Date.now }
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

const isProd = process.env.NODE_ENV === "production";
const cookieOptions = {
  httpOnly: true,
  sameSite: "lax",
  secure: isProd,
  maxAge: 1000 * 60 * 60 * 24 * 30
};

// ----- Auth routes -----
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, filiere, niveau } = req.body;
    if (!username || !password) return res.status(400).json({ error: "username et password requis" });

    const cleanUsername = xss((username || "").trim());
    const exists = await User.findOne({ username: cleanUsername });
    if (exists) return res.status(409).json({ error: "Ce pseudo existe déjà" });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({
      username: cleanUsername,
      email: email ? xss(email) : undefined,
      passwordHash,
      filiere: filiere || null,
      niveau: niveau || null
    });

    const token = signToken(user);
    res.cookie("token", token, cookieOptions);
    res.json({ ok: true, username: user.username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "username et password requis" });

    const user = await User.findOne({ username: xss(username) });
    if (!user) return res.status(401).json({ error: "Identifiants invalides" });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: "Identifiants invalides" });

    const token = signToken(user);
    res.cookie("token", token, cookieOptions);
    res.json({ ok: true, username: user.username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).lean();
    if (!user) return res.status(404).json({ error: "Not found" });
    res.json({ username: user.username, filiere: user.filiere, niveau: user.niveau });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// ----- Upload config -----
const MAX_MB = parseInt(process.env.MAX_UPLOAD_MB || "10", 10);
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (_req, file, cb) => {
    const id = uuidv4();
    const ext = path.extname(file.originalname);
    cb(null, `${id}${ext}`);
  }
});
function fileFilter(_req, file, cb) {
  const allowed = [
    "image/png", "image/jpg", "image/jpeg", "image/gif", "image/webp",
    "application/pdf",
    "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain", "application/zip"
  ];
  if (allowed.includes(file.mimetype)) cb(null, true);
  else cb(new Error("Type de fichier non autorisé"), false);
}
const upload = multer({
  storage,
  limits: { fileSize: MAX_MB * 1024 * 1024 },
  fileFilter
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

// ----- Serve index.html -----
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ----- Socket.IO -----
const onlineUsers = new Map();
const lastMessageTime = new Map();

io.use((socket, next) => {
  try {
    const cookie = socket.request.headers.cookie || "";
    const match = cookie.split(";").map(s => s.trim()).find(s => s.startsWith("token="));
    if (!match) return next();
    const token = match.split("=")[1];
    const payload = jwt.verify(token, JWT_SECRET);
    socket.user = { id: payload.id, username: payload.username };
    return next();
  } catch {
    return next();
  }
});

io.on("connection", (socket) => {
  if (socket.user?.username) {
    onlineUsers.set(socket.id, socket.user.username);
  }

  function broadcastUserList(room) {
    const sids = io.sockets.adapter.rooms.get(room) || new Set();
    const clients = Array.from(sids).map(id => {
      const s = io.sockets.sockets.get(id);
      return s?.user?.username || "Anonyme";
    });
    io.to(room).emit("userList", clients);
  }

  socket.on("joinRoom", async ({ username, room }) => {
    try {
      const cleanRoom = xss(String(room || "Général"));
      const cleanUser = xss(String(username || (socket.user?.username || "Anonyme")));
      socket.join(cleanRoom);
      socket.currentRoom = cleanRoom;

      const history = await Message.find({ room: cleanRoom }).sort({ createdAt: -1 }).limit(50).lean();
      socket.emit("history", history.reverse());

      socket.to(cleanRoom).emit("notification", `${cleanUser} a rejoint le salon`);
      broadcastUserList(cleanRoom);
    } catch (e) {
      console.error("joinRoom error:", e);
    }
  });

  socket.on("message", async (data) => {
    try {
      const now = Date.now();
      const last = lastMessageTime.get(socket.id) || 0;
      if (now - last < 2000) {
        socket.emit("notification", "⏳ Tu envoies des messages trop vite !");
        return;
      }
      lastMessageTime.set(socket.id, now);

      const room = xss(String(data.room || socket.currentRoom || "Général"));
      const user = xss(String(data.user || socket.user?.username || "Anonyme"));
      const type = data.type || "text";
      const fileUrl = data.fileUrl || null;
      const fileName = data.fileName ? xss(String(data.fileName)) : null;
      const cleanText = data.text ? xss(String(data.text)) : "";

      const doc = await Message.create({
        room,
        user,
        text: cleanText,
        type,
        fileUrl,
        fileName
      });

      io.to(room).emit("message", {
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
    } catch (e) {
      console.error("message error:", e);
    }
  });

  socket.on("react", async ({ messageId, emoji, room }) => {
    try {
      if (!messageId || !emoji) return;
      const msg = await Message.findById(messageId);
      if (!msg) return;
      const current = msg.reactions.get(emoji) || 0;
      msg.reactions.set(emoji, current + 1);
      await msg.save();
      io.to(room).emit("reactionUpdated", { messageId, emoji, count: current + 1 });
    } catch (e) {
      console.error("react error:", e);
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
});

// ----- Start server -----
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`✅ Serveur lancé sur http://localhost:${PORT}`);
});
