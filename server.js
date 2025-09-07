const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const xss = require("xss"); // <-- on ajoute cette lib
const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(__dirname));

let lastMessageTime = {}; // pour limiter le spam

io.on("connection", (socket) => {
    console.log("Nouvel utilisateur connecté");

    socket.on("joinRoom", ({ username, room }) => {
        socket.join(room);
        socket.username = username;
        socket.room = room;

        socket.to(room).emit("notification", `${username} a rejoint le salon`);
        updateUsers(room);
    });

    socket.on("message", (data) => {
        const now = Date.now();

        // Vérifie le délai (2 sec)
        if (lastMessageTime[socket.id] && now - lastMessageTime[socket.id] < 2000) {
            socket.emit("notification", "⏳ Tu envoies des messages trop vite !");
            return;
        }
        lastMessageTime[socket.id] = now;

        // Nettoyer le texte contre XSS
        const cleanText = xss(data.text);

        io.to(data.room).emit("message", {
            user: data.user,
            text: cleanText,
            time: new Date().toLocaleTimeString()
        });
    });

    socket.on("disconnect", () => {
        if (socket.room) {
            socket.to(socket.room).emit("notification", `${socket.username} a quitté`);
            updateUsers(socket.room);
        }
    });

    function updateUsers(room) {
        const clients = Array.from(io.sockets.adapter.rooms.get(room) || [])
            .map(socketId => io.sockets.sockets.get(socketId).username);
        io.to(room).emit("userList", clients);
    }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Serveur lancé sur http://localhost:${PORT}`));
