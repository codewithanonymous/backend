// Production Configuration
const config = {
    // Production API URL - points to your Render backend
    API_BASE_URL: 'https://kitsflickbackend.onrender.com',
    
    // Socket.IO configuration
    SOCKET_IO_URL: 'https://kitsflickbackend.onrender.com',
    
    // Feature flags
    ENABLE_ANALYTICS: true,
    DEBUG_MODE: false,
    
    // Timeouts (in milliseconds)
    API_TIMEOUT: 10000,  // 10 seconds
    UPLOAD_TIMEOUT: 30000,  // 30 seconds
    
    // Retry configuration
    MAX_RETRIES: 3,
    RETRY_DELAY: 1000  // 1 second
};

// Log the environment for debugging
console.log('Running in production mode');
console.log('API Base URL:', config.API_BASE_URL);

// Freeze the config object to prevent modifications
Object.freeze(config);
