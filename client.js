const socket = io();
let currentRoom = null;
let username = null;

// === DOM Elements ===
const loginModal = document.getElementById("login");
const authError = document.getElementById("authError");
const chatBox = document.getElementById("chat-box");
const headerTitle = document.getElementById("headerTitle");
const backBtn = document.getElementById("backBtn");
const roomsContainer = document.getElementById("rooms");
const mainChat = document.getElementById("main");
const messageInput = document.getElementById("messageInput");
const userList = document.getElementById("userList");

// === Buttons ===
document.getElementById("registerBtn").addEventListener("click", register);
document.getElementById("loginBtn").addEventListener("click", login);
document.getElementById("logoutBtn").addEventListener("click", logout);
document.getElementById("toggleThemeBtn").addEventListener("click", toggleTheme);
document.getElementById("sendBtn").addEventListener("click", sendMessage);
document.getElementById("pickFileBtn").addEventListener("click", () => document.getElementById("fileInput").click());

// Mobile back button
backBtn.addEventListener("click", () => {
    mainChat.classList.add("mobile-hidden");
    roomsContainer.classList.remove("mobile-hidden");
    backBtn.style.display = "none";
});

// === Filières & Niveaux ===
document.querySelectorAll(".level-btn").forEach(btn =>
    btn.addEventListener("click", () => {
        currentRoom = btn.dataset.level;
        showFiliereList();
    })
);

document.querySelectorAll(".filiere-btn").forEach(btn =>
    btn.addEventListener("click", () => joinRoom(`${currentRoom} - ${btn.dataset.filiere}`))
);

// === Functions ===
function showFiliereList() {
    // Affiche seulement les filières
    roomsContainer.classList.remove("mobile-hidden");
    mainChat.classList.add("mobile-hidden");
    backBtn.style.display = "inline-block";
}

function joinRoom(room) {
    if (!username) return alert("Connecte-toi d'abord !");
    currentRoom = room;
    socket.emit("joinRoom", { username, room });
    roomsContainer.classList.add("mobile-hidden");
    mainChat.classList.remove("mobile-hidden");
    headerTitle.textContent = room;
    chatBox.innerHTML = "";
    backBtn.style.display = "inline-block";
}

// === Auth ===
async function register() {
    const usernameInput = document.getElementById("l_username").value.trim();
    const email = document.getElementById("l_email").value.trim();
    const password = document.getElementById("l_password").value;
    const filiere = document.getElementById("l_filiere").value;
    const niveau = document.getElementById("l_niveau").value;

    try {
        const res = await fetch("/api/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: usernameInput, email, password, filiere, niveau })
        });
        const data = await res.json();
        if (data.ok) {
            username = data.username;
            loginModal.style.display = "none";
        } else authError.textContent = data.error;
    } catch (e) { authError.textContent = "Erreur serveur"; }
}

async function login() {
    const usernameInput = document.getElementById("l_username").value.trim();
    const password = document.getElementById("l_password").value;

    try {
        const res = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: usernameInput, password })
        });
        const data = await res.json();
        if (data.ok) {
            username = data.username;
            loginModal.style.display = "none";
        } else authError.textContent = data.error;
    } catch (e) { authError.textContent = "Erreur serveur"; }
}

function logout() {
    username = null;
    loginModal.style.display = "flex";
    chatBox.innerHTML = "";
    userList.innerHTML = "";
    socket.disconnect();
}

// === Chat ===
function sendMessage() {
    if (!messageInput.value.trim() || !currentRoom) return;
    socket.emit("chatMessage", { user: username, text: messageInput.value.trim(), room: currentRoom });
    messageInput.value = "";
}

// === Socket.io events ===
socket.on("history", messages => {
    chatBox.innerHTML = "";
    messages.forEach(renderMessage);
});

socket.on("message", renderMessage);

socket.on("notification", text => {
    const div = document.createElement("div");
    div.className = "notification";
    div.textContent = text;
    chatBox.appendChild(div);
    chatBox.scrollTop = chatBox.scrollHeight;
});

socket.on("users", users => {
    userList.innerHTML = "";
    users.forEach(u => {
        const li = document.createElement("li");
        li.innerHTML = `<div class="avatar">${u[0].toUpperCase()}</div>${u}`;
        userList.appendChild(li);
    });
});

// Affichage message
function renderMessage(msg) {
    const div = document.createElement("div");
    div.className = "message " + (msg.user === username ? "me" : "other");
    div.innerHTML = `<strong>${msg.user}</strong>: ${msg.text}`;
    chatBox.appendChild(div);
    chatBox.scrollTop = chatBox.scrollHeight;
}

// === Theme toggle ===
function toggleTheme() {
    document.body.dataset.theme = document.body.dataset.theme === "dark" ? "light" : "dark";
}
