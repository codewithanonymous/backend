// feed.js - Client-side logic for the SnapShare feed page
// Import config
const API_BASE_URL = window.config ? config.API_BASE_URL : '';

// Socket.IO connection URL - Use your Render backend URL directly
const SOCKET_URL = 'https://kitsflickbackend.onrender.com';

class SnapFeed {
    constructor() {
        // Check authentication first
        const user = JSON.parse(localStorage.getItem('user') || '{}');
        this.token = user?.token;
        this.user = user;
        
        // Get current page path
        const currentPath = window.location.pathname;
        const isFeedPage = currentPath.endsWith('feed.html') || currentPath.endsWith('feed');
        
        // Only redirect if we're on the feed page without authentication
        if (isFeedPage && !this.token) {
            console.log('Not authenticated, redirecting to index.html');
            window.location.href = '/index.html';
            return;
        }
        
        // If we have a token and we're on the index page, redirect to feed
        if (this.token && (currentPath.endsWith('index.html') || currentPath === '/' || currentPath === '')) {
            console.log('Already authenticated, redirecting to feed');
            window.location.href = '/feed.html';
            return;
        }

        // Initialize properties
        this.socket = null;
        this.viewedSnaps = new Set();
        this.isLoading = false;
        this.hasMore = true;
        this.page = 1;
        this.pageSize = 10;
        
        console.log('Initializing feed for user:', this.user.username || 'Unknown');
        this.initializeSocket();
        this.init();
    }

    init() {
        try {
            this.setupRefreshButton();
            this.setupScrollTracking();
            this.loadFeed();
            this.displayUsername();
        } catch (error) {
            console.error('Error initializing feed:', error);
        }
    }

    initializeSocket() {
        try {
            console.log('Initializing socket connection to:', SOCKET_URL);
            this.socket = io(SOCKET_URL, {
                path: '/socket.io/',
                transports: ['websocket', 'polling'],
                reconnectionAttempts: 5,
                reconnectionDelay: 1000,
                reconnectionDelayMax: 5000,
                timeout: 20000,
                withCredentials: true,
                auth: {
                    token: this.token
                },
                extraHeaders: {
                    "Authorization": `Bearer ${this.token}`
                }
            });

            this.socket.on('connect', () => {
                console.log('Connected to WebSocket server');
                console.log('Socket ID:', this.socket.id);
                this.updateConnectionStatus(true);
            });

            this.socket.on('connect_error', (error) => {
                console.error('Socket connection error:', error);
                this.updateConnectionStatus(false);
            });

            this.socket.on('disconnect', (reason) => {
                console.log('Disconnected from WebSocket server:', reason);
                this.updateConnectionStatus(false);
            });

            this.socket.on('newSnap', (snapData) => {
                // Don't show snaps from the current user
                if (snapData.postedBy !== (this.user && this.user.id)) {
                    this.showNewSnapAlert();
                }
            });

        } catch (error) {
            console.error('Socket initialization error:', error);
        }
    }

    setupRefreshButton() {
        const refreshFeedBtn = document.getElementById('refreshFeed');
        if (refreshFeedBtn) {
            refreshFeedBtn.addEventListener('click', () => {
                this.refreshFeed();
            });
        }
    }
    
    setupScrollTracking() {
        window.addEventListener('scroll', this.checkViewedSnaps.bind(this));
    }

    updateConnectionStatus(connected) {
        const statusIndicator = document.getElementById('connectionStatus');
        if (!statusIndicator) {
            console.warn('Connection status indicator not found in the DOM');
            return;
        }
        
        const statusText = statusIndicator.querySelector('.status-text');
        const statusDot = statusIndicator.querySelector('.status-dot');
        
        if (statusText) {
            statusText.textContent = connected ? 'Connected' : 'Connecting...';
        }
        
        if (statusDot) {
            statusDot.style.background = connected ? '#10B981' : '#F59E0B';
        }
    }

    showNewSnapAlert() {
        const newSnapAlert = document.getElementById('newSnapAlert');
        if (!newSnapAlert) return;
        newSnapAlert.style.display = 'flex';
        
        // Auto-hide after 10 seconds
        setTimeout(() => {
            newSnapAlert.style.display = 'none';
        }, 10000);
    }

    displayUsername() {
        const username = this.user?.username;
        const usernameElement = document.getElementById('loggedInUsername');
        
        if (usernameElement && this.user && this.user.username) {
            usernameElement.textContent = `Hi, ${username}`;
        }
    }

    // Helper method to make authenticated fetch requests
    async fetchWithAuth(endpoint) {
        return fetch(endpoint, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${this.token}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            credentials: 'include'
        });
    }

    async loadFeed() {
        console.log('loadFeed called. Page:', this.page, 'Loading:', this.isLoading, 'Has more:', this.hasMore);
        
        if (this.isLoading) {
            console.log('Already loading, skipping...');
            return;
        }
        
        if (!this.hasMore) {
            console.log('No more content to load');
            return;
        }
        
        this.isLoading = true;
        const snapFeed = document.getElementById('snapFeed');
        
        if (!snapFeed) {
            console.error('snapFeed element not found in the DOM!');
            this.isLoading = false;
            return;
        }
        
        try {
            // Show loading state
            if (this.page === 1) {
                console.log('First page load, showing loading state');
                snapFeed.innerHTML = `
                    <div class="loading-card" style="height: 600px; margin: 16px; border-radius: 12px; background: #f0f0f0;"></div>
                    <div class="loading-card" style="height: 600px; margin: 16px; border-radius: 12px; background: #f0f0f0;"></div>
                `;
            } else {
                console.log('Loading more content, page:', this.page);
            }
            
            console.log('Fetching feed data...');
            let endpoint, response;
            
            try {
                // Try /api/feed first
              endpoint = `${config.API_BASE_URL}/api/feed?page=${this.page}&limit=${this.pageSize}`;
                console.log('Attempting to fetch from:', endpoint);
                response = await this.fetchWithAuth(endpoint);
                console.log('Response status:', response.status);
                
                // If 404, try the legacy /api/snaps endpoint
                if (response.status === 404) {
                    console.log('Feed endpoint not found, trying legacy snaps endpoint...');
                  endpoint = `${config.API_BASE_URL}/api/snaps`;
                    console.log('Attempting to fetch from:', endpoint);
                    response = await this.fetchWithAuth(endpoint);
                    console.log('Legacy endpoint response status:', response.status);
                }
                
                if (!response.ok) {
                    const errorText = await response.text();
                    console.error('API Error Response:', {
                        status: response.status,
                        statusText: response.statusText,
                        url: response.url,
                        error: errorText
                    });
                }
            } catch (error) {
                console.error('Error during fetch:', {
                    message: error.message,
                    stack: error.stack,
                    endpoint: endpoint
                });
                throw error; // Re-throw to be caught by the outer try-catch
            }

            console.log('Response status:', response.status);
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                console.error('API Error:', errorData);
                
                if (response.status === 401 || response.status === 403) {
                    console.log('Authentication failed, redirecting to index.html');
                    localStorage.removeItem('token');
                    localStorage.removeItem('user');
                    window.location.href = '/index.html';
                    return;
                }
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            console.log('Received data:', data);
            
            // Handle both response formats
            let newSnaps = [];
            let recentlyViewedSnaps = [];
            
            if (data.snaps && Array.isArray(data.snaps)) {
                // New format: { success: true, snaps: [...], pagination: {...} }
                newSnaps = data.snaps;
            } else if (data.newSnaps && data.recentlyViewedSnaps) {
                // Old format: { newSnaps: [...], recentlyViewedSnaps: [...] }
                newSnaps = data.newSnaps;
                recentlyViewedSnaps = data.recentlyViewedSnaps;
            }
            
            const hasNewSnaps = newSnaps.length > 0;
            const hasRecentSnaps = recentlyViewedSnaps.length > 0;
            
            console.log(`Processing ${newSnaps.length} new snaps and ${recentlyViewedSnaps.length} recently viewed snaps`);
            
            // If first page and no snaps, show empty state
            if (this.page === 1 && !hasNewSnaps && !hasRecentSnaps) {
                console.log('No snaps found, showing empty state');
                snapFeed.innerHTML = `
                    <div style="text-align: center; padding: 2rem; border: 2px dashed #eee; border-radius: 8px; margin: 1rem;">
                        <i class="fas fa-camera" style="font-size: 3rem; color: #ddd; margin-bottom: 1rem; display: block;"></i>
                        <h3>No snaps available</h3>
                        <p>Be the first to share a snap!</p>
                    </div>
                `;
                return;
            }
            
            // Update hasMore flag based on newSnaps (assuming pagination applies to new snaps)
            if (this.page === 1) {
                snapFeed.innerHTML = ''; // Clear loading cards
                this.hasMore = hasNewSnaps && newSnaps.length >= this.pageSize;
            } else {
                this.hasMore = hasNewSnaps && newSnaps.length >= this.pageSize;
            }
            
            // If no more content and not first page, show end of feed message
            if (this.page > 1 && !hasNewSnaps && !hasRecentSnaps) {
                console.log('Reached end of feed');
                const endOfFeed = document.createElement('div');
                endOfFeed.className = 'end-of-feed';
                endOfFeed.style.cssText = `
                    text-align: center;
                    padding: 2rem;
                    color: #666;
                    font-size: 1.1rem;
                    border-top: 1px solid #eee;
                    margin-top: 1rem;
                `;
                endOfFeed.textContent = 'You have seen all snaps. Come back later for more!';
                snapFeed.appendChild(endOfFeed);
                this.hasMore = false;
                return;
            }
            
            // Create a document fragment for better performance
            const fragment = document.createDocumentFragment();
            let snapCount = 0;
            
            // Function to process and add snaps to the fragment
            const processSnaps = (snaps, isNew = true) => {
                if (!Array.isArray(snaps)) return;
                
                snaps.forEach((snap, index) => {
                    try {
                        // Add a flag to indicate if it's a new snap
                        const snapWithType = { ...snap, isNew };
                        console.log(`Creating element for ${isNew ? 'new' : 'recent'} snap ${index + 1}:`, snapWithType);
                        
                        const snapElement = this.createSnapElement(snapWithType);
                        if (snapElement) {
                            // Add data attributes for debugging
                            snapElement.setAttribute('data-snap-id', snap.id || `snap-${Date.now()}-${index}`);
                            snapElement.style.border = '1px solid #eee';
                            snapElement.style.marginBottom = '1rem';
                            snapElement.style.padding = '1rem';
                            snapElement.style.borderRadius = '8px';
                            snapElement.style.backgroundColor = '#fff';
                            
                            fragment.appendChild(snapElement);
                            snapCount++;
                        } else {
                            console.error('Failed to create element for snap:', snapWithType);
                        }
                    } catch (error) {
                        console.error(`Error creating snap element ${index + 1}:`, error, snap);
                    }
                });
            };
            
            // Process new snaps first, then recently viewed
            if (hasNewSnaps) processSnaps(newSnaps, true);
            if (hasRecentSnaps) processSnaps(recentlyViewedSnaps, false);
            
            // Append all snaps at once
            if (snapCount > 0) {
                snapFeed.appendChild(fragment);
                console.log(`Successfully added ${snapCount} snaps to the feed`);
                
                // Initialize animations for new elements
                this.initScrollAnimations();
                this.page++;
                
                // Debug: Log the current state of the feed container
                console.log('Feed container now has', snapFeed.children.length, 'children');
                console.log('Feed container HTML:', snapFeed.outerHTML);
            } else {
                console.warn('No valid snap elements were created');
            }
            
        } catch (error) {
            console.error('Feed loading error:', error);
            this.showError('Failed to load feed. Please try again.');
        } finally {
            this.isLoading = false;
        }
    }

    refreshFeed() {
        const snapsContainer = document.getElementById('snapsContainer');
        const newSnapAlert = document.getElementById('newSnapAlert');
        
        if (snapsContainer) snapsContainer.innerHTML = '';
        if (newSnapAlert) newSnapAlert.style.display = 'none';
        this.viewedSnaps.clear();
        
        const loadingMessage = document.getElementById('loadingMessage');
        if (loadingMessage) loadingMessage.style.display = 'flex';
        this.loadFeed();
    }

    renderSnaps(snaps) {
        const snapsContainer = document.getElementById('snapsContainer');
        if (!snapsContainer) return;

        snapsContainer.innerHTML = '';
        
        snaps.forEach(snap => {
            if (!this.viewedSnaps.has(snap.id)) {
                const snapElement = this.createSnapElement(snap);
                snapsContainer.appendChild(snapElement);
            }
        });
    }

    /**
     * Normalizes image URLs to ensure they work correctly
     * @param {string} url - The URL to normalize
     * @returns {string} Normalized URL
     */
    normalizeImageUrl(url) {
        if (!url || typeof url !== 'string') return '';
        
        // If it's already a full URL, return as is
        if (url.startsWith('http')) {
            return url;
        }
        
        // If it's an API endpoint, return as is (don't add /uploads/)
     if (url.startsWith('/api/') || url.startsWith(config.API_BASE_URL + '/api/')) {
    return url.startsWith('http') ? url : config.API_BASE_URL + url;
}
        
        // Remove any leading/trailing slashes
        let path = url.trim().replace(/^[\\/]+|[\\/]+$/g, '');
        
        // If the path already starts with uploads, remove it to avoid duplicates
        if (path.toLowerCase().startsWith('uploads/')) {
            path = path.substring(8);
        }
        
        // For all other cases, assume it's a static file in /uploads/
        const normalizedPath = '/uploads/' + path.replace(/^[\\/]+/, '');
        
        // Clean up any remaining double slashes
        return normalizedPath.replace(/([^:]\/)\/+/g, '$1');
    }
    
    /**
     * Handles image loading errors by showing a placeholder
     * @param {Event} event - The error event
     */
    handleImageError(event) {
        const img = event.target;
        if (!img) return;
        
        // Set a placeholder image
        img.src = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI0MDAiIGhlaWdodD0iNDAwIiB2aWV3Qm94PSIwIDAgNDAwIDQwMCI+PHJlY3Qgd2lkdGg9IjQwMCIgaGVpZ2h0PSI0MDAiIGZpbGw9IiNmNWY1ZjUiLz48dGV4dCB4PSI1MCUiIHk9IjUwJSIgZm9udC1mYW1pbHk9IkFyaWFsIiBmb250LXNpemU9IjE0IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBhbGlnbm1lbnQtYmFzZWxpbmU9Im1pZGRsZSIgZmlsbD0iIzk5OSI+SW1hZ2Ugbm90IGF2YWlsYWJsZTwvdGV4dD48L3N2Zz4=';
        img.alt = 'Image not available';
        img.style.objectFit = 'contain';
        img.style.backgroundColor = '#f5f5f5';
        
        // Remove the onerror handler to prevent infinite loops
        img.onerror = null;
        
        console.warn('Failed to load image:', img.src);
    }
    handleImageError(event) {
        const img = event.target;
        if (!img.hasAttribute('data-error-handled')) {
            img.setAttribute('data-error-handled', 'true');
            img.src = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI0MDAiIGhlaWdodD0iNDAwIiB2aWV3Qm94PSIwIDAgNDAwIDQwMCI+PHJlY3Qgd2lkdGg9IjQwMCIgaGVpZ2h0PSI0MDAiIGZpbGw9IiNlZWVlZWUiLz48dGV4dCB4PSI1MCUiIHk9IjUwJSIgZm9udC1mYW1pbHk9IkFyaWFsIiBmb250LXNpemU9IjE0IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBhbGlnbm1lbnQtYmFzZWxpbmU9Im1pZGRsZSIgZmlsbD0iIzk5OSI+SW1hZ2Ugbm90IGZvdW5kPC90ZXh0Pjwvc3ZnPg=';
            img.alt = 'Image not found';
            img.style.objectFit = 'contain';
            img.style.backgroundColor = '#f5f5f5';
        }
    }

    createSnapElement(snap) {
        if (!snap) {
            console.error('createSnapElement called with null/undefined snap');
            return null;
        }
        
        console.log('Creating snap element:', { 
            id: snap.id, 
            imageUrl: snap.imageUrl,
            isNew: snap.isNew
        });
        
        try {
            // Safely extract data with fallbacks
            const createdAt = snap.createdAt || snap.created_at || new Date().toISOString();
            const timeAgo = this.getTimeAgo(new Date(createdAt));
            
            // Extract username with better fallback handling
            const username = snap.username || snap.uploader_username || snap.user?.username || 'Anonymous';
            const userInitial = username.charAt(0).toUpperCase();
            const caption = snap.caption || '';
            const location = snap.location ? `<div class="location">📍 ${snap.location}</div>` : '';
            const hashtags = Array.isArray(snap.hashtags) ? snap.hashtags : 
                            (snap.hashtags ? snap.hashtags.split(',').map(tag => tag.trim()).filter(Boolean) : []);
            
            // Get and normalize the image URL
            const imageUrl = snap.imageUrl || snap.image_path || '';
            const imageSrc = imageUrl ? this.normalizeImageUrl(imageUrl) : '';
            
            // Create the main snap card
            const snapCard = document.createElement('article');
            snapCard.className = 'snap-card';
            snapCard.dataset.snapId = snap.id || `unknown-${Date.now()}`;
            
            // Add visual styles
            snapCard.style.cssText = `
                position: relative;
                margin: 0 0 24px 0;
                border-radius: 16px;
                background: #fff;
                box-shadow: 0 4px 20px rgba(0,0,0,0.06);
                overflow: hidden;
                transition: transform 0.2s ease, box-shadow 0.2s ease;
            `;
            
            // Add hover effect
            snapCard.onmouseenter = () => {
                snapCard.style.transform = 'translateY(-2px)';
                snapCard.style.boxShadow = '0 8px 25px rgba(0,0,0,0.1)';
            };
            snapCard.onmouseleave = () => {
                snapCard.style.transform = 'translateY(0)';
                snapCard.style.boxShadow = '0 4px 20px rgba(0,0,0,0.06)';
            };
            
            // Build the HTML template
            const template = `
                <div class="snap-header" style="
                    display: flex;
                    align-items: center;
                    padding: 16px;
                    border-bottom: 1px solid #f0f0f0;">
                    <div class="user-avatar" style="
                        width: 40px;
                        height: 40px;
                        border-radius: 50%;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        color: white;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        margin-right: 12px;
                        font-weight: 600;
                        font-size: 1rem;
                        flex-shrink: 0;
                    ">
                        ${userInitial}
                    </div>
                    <div class="user-info" style="flex: 1; min-width: 0;">
                        <div class="username" style="
                            font-weight: 600;
                            font-size: 0.95rem;
                            color: #262626;
                            white-space: nowrap;
                            overflow: hidden;
                            text-overflow: ellipsis;">
                            ${username}
                        </div>
                        <div class="timestamp" style="
                            font-size: 0.75rem;
                            color: #8e8e8e;
                            margin-top: 2px;">
                            ${timeAgo} ${location}
                        </div>
                    </div>
                    ${snap.isNew ? `
                    <div class="new-badge" style="
                        background: #FF4081;
                        color: white;
                        padding: 4px 8px;
                        border-radius: 12px;
                        font-size: 0.7rem;
                        font-weight: 600;
                        letter-spacing: 0.5px;
                        text-transform: uppercase;">
                        New
                    </div>` : ''}
                </div>
                
                <div class="snap-image-container" style="
                    position: relative;
                    width: 100%;
                    padding-top: 100%;
                    background: #fafafa;
                    overflow: hidden;">
                    <img 
                        src="${imageSrc}" 
                        alt="${caption || 'Snap image'}"
                        loading="lazy"
                        style="
                            position: absolute;
                            top: 0;
                            left: 0;
                            width: 100%;
                            height: 100%;
                            object-fit: cover;
                            transition: transform 0.5s ease;
                        "
                        onerror="this.onerror=null; this.src='data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI0MDAiIGhlaWdodD0iNDAwIiB2aWV3Qm94PSIwIDAgNDAwIDQwMCI+PHJlY3Qgd2lkdGg9IjQwMCIgaGVpZ2h0PSI0MDAiIGZpbGw9IiNmNWY1ZjUiLz48dGV4dCB4PSI1MCUiIHk9IjUwJSIgZm9udC1mYW1pbHk9IkFyaWFsIiBmb250LXNpemU9IjE0IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBhbGlnbm1lbnQtYmFzZWxpbmU9Im1pZGRsZSIgZmlsbD0iIzk5OSI+SW1hZ2Ugbm90IGF2YWlsYWJsZTwvdGV4dD48L3N2Zz4='; this.style.objectFit='contain'; this.style.backgroundColor='#f5f5f5'"
                    >
                </div>
                
                <div class="snap-actions" style="
                    padding: 12px 16px;
                    display: flex;
                    align-items: center;
                    border-bottom: 1px solid #f0f0f0;">
                    <div class="action-buttons" style="display: flex; gap: 16px;">
                        <button class="like-button" style="background: none; border: none; cursor: pointer;">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"></path>
                            </svg>
                        </button>
                        <button class="comment-button" style="background: none; border: none; cursor: pointer;">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"></path>
                            </svg>
                        </button>
                        <button class="share-button" style="background: none; border: none; cursor: pointer;">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"></path>
                                <polyline points="16 6 12 2 8 6"></polyline>
                                <line x1="12" y1="2" x2="12" y2="15"></line>
                            </svg>
                        </button>
                    </div>
                </div>
                
                <div class="snap-caption" style="padding: 12px 16px 16px;">
                    ${caption ? `<div class="caption" style="
                        font-size: 0.95rem;
                        line-height: 1.4;
                        margin-bottom: 8px;
                        color: #262626;
                        white-space: pre-line;
                        word-break: break-word;">
                        ${caption}
                    </div>` : ''}
                    
                    ${hashtags.length > 0 ? `
                    <div class="hashtags" style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px;">
                        ${hashtags.map(tag => `
                            <span class="hashtag" style="
                                display: inline-block;
                                background: #f0f2f5;
                                color: #1a73e8;
                                padding: 4px 10px;
                                border-radius: 12px;
                                font-size: 0.75rem;
                                font-weight: 500;">
                                #${tag}
                            </span>
                        `).join('')}
                    </div>` : ''}
                </div>
            `;
            
            snapCard.innerHTML = template;
            
            // Add global error handler if not exists
            if (!window.snapFeed) {
                window.snapFeed = this;
            }
            
            return snapCard;
        } catch (error) {
            console.error('Error in createSnapElement:', error, snap);
            
            // Return a simple error card if something goes wrong
            const errorCard = document.createElement('div');
            errorCard.className = 'error-card';
            errorCard.style.padding = '20px';
            errorCard.style.border = '1px solid #ff4444';
            errorCard.style.borderRadius = '8px';
            errorCard.style.backgroundColor = '#ffebee';
            errorCard.style.color = '#c62828';
            errorCard.textContent = 'Error loading snap';
            
            return errorCard;
        }
    }

    setupScrollTracking() {
        const feedContainer = document.querySelector('.feed-container');
        if (!feedContainer) return;
        let isScrolling = false;
        
        feedContainer.addEventListener('scroll', () => {
            if (!isScrolling) {
                isScrolling = true;
                
                setTimeout(() => {
                    this.checkViewedSnaps();
                    isScrolling = false;
                }, 100);
            }
        });
    }

    checkViewedSnaps() {
        const snapCards = document.querySelectorAll('.snap-card:not(.snap-viewed)');
        const viewportHeight = window.innerHeight;
        
        snapCards.forEach(snapCard => {
            const rect = snapCard.getBoundingClientRect();
            const snapId = parseInt(snapCard.dataset.snapId);
            
            // If snap has scrolled past the top of viewport, mark as viewed
            if (rect.bottom < viewportHeight * 0.5 && !this.viewedSnaps.has(snapId)) {
                this.markSnapAsViewed(snapId, snapCard);
            }
        });
    }

    async markSnapAsViewed(snapId, snapElement) {
        try {
            this.viewedSnaps.add(snapId);
            
            // Add visual effect
            snapElement.classList.add('snap-viewed');
            
            // Remove from DOM after animation
            setTimeout(() => {
                if (snapElement.parentNode) {
                    snapElement.remove();
                    this.checkIfFeedEmpty();
                }
            }, 500);
            
            // Mark as viewed on server
     const response = await fetch(`${config.API_BASE_URL}/api/snap/view`, {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({ snapId })
});

            // Check for unauthorized status codes and redirect
            if (response.status === 401 || response.status === 403) {
                console.error("Authentication failed for snap view, redirecting.");
                this.handleLogout();
                return;
            }

            if (!response.ok) {
                console.error('Failed to mark snap as viewed');
            }
            
        } catch (error) {
            console.error('Error marking snap as viewed:', error);
        }
    }

    checkIfFeedEmpty() {
        const snapsContainer = document.getElementById('snapsContainer');
        const emptyFeed = document.getElementById('emptyFeed');
        
        if (snapsContainer && emptyFeed) {
            if (snapsContainer.children.length === 0) {
                emptyFeed.style.display = 'flex';
            }
        }
    }

    getTimeAgo(date) {
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / (1000 * 60));
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        
        if (diffMins < 1) return 'just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        return `${Math.floor(diffHours / 24)}d ago`;
    }

    handleLogout() {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        
        if (this.socket) {
            this.socket.disconnect();
        }
        
        // Redirect to index.html after logout
        window.location.href = '/index.html';
    }

    showError(message) {
        const errorElement = document.getElementById('errorMessage');
        if (!errorElement) return;
        errorElement.textContent = message;
        errorElement.classList.add('show');
        
        setTimeout(() => {
            errorElement.classList.remove('show');
        }, 5000);
    }
}

// Global error handler to prevent uncaught errors from causing infinite loops
window.addEventListener('error', (event) => {
    console.error('Global error caught:', event.error);
    event.preventDefault();
    return false;
});

// Track initialization state
let isInitializing = false;

// Initialize feed when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Prevent multiple initializations
    if (isInitializing) {
        console.log('Initialization already in progress');
        return;
    }
    
    isInitializing = true;
    
    try {
        // Only create instance if not already created
        if (!window.snapFeedInstance) {
            console.log('Creating new SnapFeed instance');
            window.snapFeedInstance = new SnapFeed();
        } else if (window.snapFeedInstance.init) {
            console.log('Reinitializing existing SnapFeed instance');
            window.snapFeedInstance.init();
        }
    } catch (error) {
        console.error('Error during initialization:', error);
        // Prevent infinite loops by showing error to user
        alert('Failed to initialize the application. Please refresh the page.');
    } finally {
        isInitializing = false;
    }
});
