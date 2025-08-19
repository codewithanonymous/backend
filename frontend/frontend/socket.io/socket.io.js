// socket.js - Handles all real-time communication via Socket.IO
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// We need to use the same JWT secret key for token validation.
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key_here';

let io; // This will hold our Socket.IO server instance

function initSocket(server) {
    // Initialize the Socket.IO server and attach it to the main HTTP server.
    // 'path' is important if you're hosting on a sub-path.
    io = new Server(server, {
        cors: {
            origin: '*', // Allow connections from all origins during development
            methods: ['GET', 'POST']
        }
    });

    // Middleware to authenticate users before they can connect
    io.use((socket, next) => {
        const token = socket.handshake.auth.token;
        if (!token) {
            return next(new Error('Authentication error: Token not provided'));
        }
        
        try {
            // Verify the JWT token
            const decoded = jwt.verify(token, JWT_SECRET);
            socket.user = decoded; // Attach user information to the socket object
            next();
        } catch (error) {
            next(new Error('Authentication error: Invalid token'));
        }
    });

    // Main connection handler
    io.on('connection', (socket) => {
        console.log(`User connected: ${socket.user.username} (ID: ${socket.user.id})`);
        
        // Log snapViewed event from client
        socket.on('snapViewed', (data) => {
            console.log(`User ${socket.user.username} viewed snap ID: ${data.snapId}`);
            // No need to broadcast this event to others in this implementation
        });

        // Handle disconnects
        socket.on('disconnect', () => {
            console.log(`User disconnected: ${socket.user.username}`);
        });
    });

    // You can also add more event listeners here for other real-time features.
}

// Function to emit a 'newSnap' event to all connected clients
// This should be called from your main server logic (e.g., in the /api/upload route)
function emitNewSnap(snapData) {
    console.log('Emitting newSnap event to all clients.');
    io.emit('newSnap', snapData);
}

module.exports = {
    initSocket,
    emitNewSnap
};
