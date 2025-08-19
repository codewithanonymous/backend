// public/js/utils.js - Frontend utility functions

// Displays a message to the user in a styled box
function showMessage(message, type = 'success') {
    const messageContainer = document.getElementById('message-container');
    if (!messageContainer) return;

    messageContainer.innerHTML = `<div class="message-box ${type}">${message}</div>`;
    
    // Clear message after 5 seconds
    setTimeout(() => {
        messageContainer.innerHTML = '';
    }, 5000);
}
