// Frontend configuration
const config = {
    // Use the current host for API requests in production
    // This handles both local development and production deployment
    API_BASE_URL: window.location.hostname === 'localhost' 
        ? 'http://localhost:3000' 
        : window.location.protocol + '//' + window.location.host
};

// For testing in console
console.log('Environment:', {
    hostname: window.location.hostname,
    protocol: window.location.protocol,
    href: window.location.href,
    API_BASE_URL: config.API_BASE_URL
});
