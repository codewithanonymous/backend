// socket.js - Socket.IO setup and event handling
const { Server } = require('socket.io');

let io;

// Initialize Socket.IO with the HTTP server
function initSocket(server) {
    const allowedOrigins = [
        'https://kitsflick-frontend.onrender.com',
        'http://localhost:3000'
    ];

    io = new Server(server, {
        cors: {
            origin: (origin, callback) => {
                if (!origin || allowedOrigins.includes(origin)) {
                    callback(null, true);
                } else {
                    console.log('Socket.IO connection blocked from origin:', origin);
                    callback(new Error('Not allowed by CORS'));
                }
            },
            methods: ['GET', 'POST'],
            credentials: true
        },
        path: '/socket.io/'
    });

    io.on('connection', (socket) => {
        console.log('New client connected:', socket.id);

        // Handle authentication
        const token = socket.handshake.auth.token;
        if (!token) {
            console.log('Client disconnected: No token provided');
            return socket.disconnect(true);
        }

        try {
            // Verify JWT token
            jwt.verify(token, process.env.JWT_SECRET);
        } catch (error) {
            console.log('Client disconnected: Invalid token');
            return socket.disconnect(true);
        }

        socket.on('disconnect', (reason) => {
            console.log(`Client disconnected (${socket.id}):`, reason);
        });

        // Handle errors
        socket.on('error', (error) => {
            console.error('Socket error:', error);
        });
    });

    return io;
}

// Emit a new snap to all connected clients
function emitNewSnap(snapData) {
    if (!io) {
        console.error('Socket.IO not initialized');
        return;
    }
    
    try {
        io.emit('new_snap', snapData);
        console.log('New snap emitted to clients');
    } catch (error) {
        console.error('Error emitting new snap:', error);
    }
}

module.exports = {
    initSocket,
    emitNewSnap
};
