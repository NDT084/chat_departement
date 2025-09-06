const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// 👉 Sert les fichiers statiques (HTML, CSS, JS…)
app.use(express.static(__dirname));

// Route principale
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

io.on("connection", (socket) => {
    console.log("Un utilisateur est connecté");

    socket.on("joinRoom", ({ username, room }) => {
        socket.join(room);
        socket.to(room).emit("notification", `${username} a rejoint ${room} 🎉`);

        // Rafraîchir la liste des utilisateurs du salon
        const usersInRoom = [];
        for (let [id, s] of io.of("/").sockets) {
            if (s.rooms.has(room)) usersInRoom.push(s.username || "Anonyme");
        }
        io.to(room).emit("userList", usersInRoom);

        socket.username = username;
        socket.room = room;
    });

    socket.on("message", (data) => {
        io.to(socket.room).emit("message", {
            user: data.user,
            text: data.text,
            time: new Date().toLocaleTimeString()
        });
    });

    socket.on("disconnect", () => {
        if (socket.room) {
            socket.to(socket.room).emit("notification", `${socket.username} a quitté`);
        }
        console.log("Un utilisateur est parti");
    });
});

// 👉 Render fournit le port via process.env.PORT
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Serveur lancé sur http://localhost:${PORT}`);
});
