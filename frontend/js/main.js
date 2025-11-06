// ============================================================================
// iNodes Frontend - Main Application & Authentication
// Pure JavaScript - CSP Compliant
// ============================================================================

(function() {
  'use strict';

  // ============================================================================
  // GLOBAL STATE
  // ============================================================================
  
  window.iNodesApp = {
    user: null,
    accessToken: null,
    refreshToken: null,
    deviceId: null,
    socket: null,
    currentView: 'feed',
    currentChat: null,
    unreadCounts: {
      messages: 0,
      notifications: 0
    },
    isAuthenticated: false
  };

  // ============================================================================
  // CONFIGURATION
  // ============================================================================
  
  // Detect if running on live server or actual server
  const isLiveServer = window.location.port === '5500' || window.location.port === '5501';
  const API_BASE = isLiveServer ? 'http://localhost:4000' : '';
  const SOCKET_URL = isLiveServer ? 'http://localhost:4000' : window.location.origin;

  console.log('API Base URL:', API_BASE);
  console.log('Socket URL:', SOCKET_URL);

  // ============================================================================
  // UTILITY FUNCTIONS
  // ============================================================================

  window.iNodesUtils = {
    // Generate device ID
    generateDeviceId: function() {
      return 'device_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    },

    // Format date
    formatDate: function(date) {
      const d = new Date(date);
      const now = new Date();
      const diff = now - d;
      const seconds = Math.floor(diff / 1000);
      const minutes = Math.floor(seconds / 60);
      const hours = Math.floor(minutes / 60);
      const days = Math.floor(hours / 24);

      if (seconds < 60) return 'just now';
      if (minutes < 60) return minutes + 'm';
      if (hours < 24) return hours + 'h';
      if (days < 7) return days + 'd';
      return d.toLocaleDateString();
    },

    // Format time
    formatTime: function(date) {
      return new Date(date).toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit'
      });
    },

    // Escape HTML
    escapeHtml: function(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    },

    // Get default avatar
    getDefaultAvatar: function() {
      return 'data:image/svg+xml,%3Csvg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"%3E%3Ccircle cx="50" cy="50" r="50" fill="%23667eea"/%3E%3Ctext x="50" y="50" text-anchor="middle" dy=".3em" fill="white" font-size="40" font-family="Arial"%3E👤%3C/text%3E%3C/svg%3E';
    },

    // Validate email
    validateEmail: function(email) {
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    },

    // Validate username
    validateUsername: function(username) {
      return /^[a-zA-Z0-9._-]{3,30}$/.test(username);
    },

    // Validate password
    validatePassword: function(password) {
      return password.length >= 8 && /\d/.test(password) && /[a-zA-Z]/.test(password);
    },

    // Show toast notification
    showToast: function(message, type) {
      type = type || 'info';
      const container = document.getElementById('toast-container');
      if (!container) return;

      const toast = document.createElement('div');
      toast.className = 'toast toast-' + type;
      toast.textContent = message;
      
      container.appendChild(toast);
      
      setTimeout(function() {
        toast.classList.add('show');
      }, 10);

      setTimeout(function() {
        toast.classList.remove('show');
        setTimeout(function() {
          if (toast.parentNode) {
            container.removeChild(toast);
          }
        }, 300);
      }, 3000);
    },

    // Debounce function
    debounce: function(func, wait) {
      let timeout;
      return function executedFunction() {
        const context = this;
        const args = arguments;
        clearTimeout(timeout);
        timeout = setTimeout(function() {
          func.apply(context, args);
        }, wait);
      };
    },

    // Throttle function
    throttle: function(func, limit) {
      let inThrottle;
      return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
          func.apply(context, args);
          inThrottle = true;
          setTimeout(function() {
            inThrottle = false;
          }, limit);
        }
      };
    }
  };

  // ============================================================================
  // STORAGE UTILITIES
  // ============================================================================

  window.iNodesStorage = {
    set: function(key, value) {
      try {
        localStorage.setItem('inodes_' + key, JSON.stringify(value));
      } catch (e) {
        console.error('Storage error:', e);
      }
    },

    get: function(key) {
      try {
        const item = localStorage.getItem('inodes_' + key);
        return item ? JSON.parse(item) : null;
      } catch (e) {
        console.error('Storage error:', e);
        return null;
      }
    },

    remove: function(key) {
      try {
        localStorage.removeItem('inodes_' + key);
      } catch (e) {
        console.error('Storage error:', e);
      }
    },

    clear: function() {
      try {
        const keys = Object.keys(localStorage);
        keys.forEach(function(key) {
          if (key.startsWith('inodes_')) {
            localStorage.removeItem(key);
          }
        });
      } catch (e) {
        console.error('Storage error:', e);
      }
    }
  };

  // ============================================================================
  // API CLIENT
  // ============================================================================

  window.iNodesAPI = {
    // Base request function
    request: async function(endpoint, options) {
      options = options || {};
      const headers = options.headers || {};

      // Add auth token if available
      if (window.iNodesApp.accessToken && !options.skipAuth) {
        headers['Authorization'] = 'Bearer ' + window.iNodesApp.accessToken;
      }

      // Set content type if not FormData
      if (!(options.body instanceof FormData)) {
        headers['Content-Type'] = 'application/json';
      }

      const config = {
        method: options.method || 'GET',
        headers: headers
      };

      if (options.body) {
        if (options.body instanceof FormData) {
          config.body = options.body;
          delete config.headers['Content-Type']; // Let browser set it
        } else {
          config.body = JSON.stringify(options.body);
        }
      }

      try {
        const url = API_BASE + endpoint;
        console.log('API Request:', config.method, url);
        
        const response = await fetch(url, config);
        
        // Check if response is JSON
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
          throw new Error('Server returned non-JSON response. Check if backend is running on port 4000');
        }

        const data = await response.json();

        // Handle token refresh on 401
        if (response.status === 401 && !options.skipAuth && !options.isRefresh) {
          console.log('Token expired, attempting refresh...');
          const refreshed = await window.iNodesAPI.refreshAccessToken();
          if (refreshed) {
            return await window.iNodesAPI.request(endpoint, options);
          } else {
            window.iNodesAuth.logout();
            throw new Error('Session expired');
          }
        }

        if (!data.success) {
          throw new Error(data.error || 'Request failed');
        }

        return data.data;
      } catch (error) {
        console.error('API Error:', error);
        throw error;
      }
    },

    // Refresh access token
    refreshAccessToken: async function() {
      try {
        const refreshToken = window.iNodesApp.refreshToken;
        const deviceId = window.iNodesApp.deviceId;

        if (!refreshToken || !deviceId) return false;

        const data = await window.iNodesAPI.request('/api/auth/refresh', {
          method: 'POST',
          body: { refreshToken: refreshToken, deviceId: deviceId },
          skipAuth: true,
          isRefresh: true
        });

        window.iNodesApp.accessToken = data.accessToken;
        window.iNodesApp.refreshToken = data.refreshToken;
        
        window.iNodesStorage.set('accessToken', data.accessToken);
        window.iNodesStorage.set('refreshToken', data.refreshToken);

        return true;
      } catch (error) {
        console.error('Token refresh failed:', error);
        return false;
      }
    },

    // Auth endpoints
    auth: {
      register: function(userData) {
        return window.iNodesAPI.request('/api/auth/register', {
          method: 'POST',
          body: userData,
          skipAuth: true
        });
      },

      login: function(credentials) {
        return window.iNodesAPI.request('/api/auth/login', {
          method: 'POST',
          body: credentials,
          skipAuth: true
        });
      },

      logout: function() {
        return window.iNodesAPI.request('/api/auth/logout', {
          method: 'POST',
          body: {
            refreshToken: window.iNodesApp.refreshToken,
            deviceId: window.iNodesApp.deviceId
          }
        }).catch(function(err) {
          console.log('Logout request failed, but continuing:', err);
          return { message: 'Logged out' };
        });
      }
    },

    // User endpoints
    users: {
      getMe: function() {
        return window.iNodesAPI.request('/api/users/me');
      },

      updateProfile: function(formData) {
        return window.iNodesAPI.request('/api/users/me', {
          method: 'PUT',
          body: formData
        });
      },

      getProfile: function(username) {
        return window.iNodesAPI.request('/api/users/' + username);
      },

      follow: function(userId) {
        return window.iNodesAPI.request('/api/users/' + userId + '/follow', {
          method: 'POST'
        });
      },

      block: function(userId) {
        return window.iNodesAPI.request('/api/users/' + userId + '/block', {
          method: 'POST'
        });
      }
    },

    // Post endpoints
    posts: {
      create: function(formData) {
        return window.iNodesAPI.request('/api/posts', {
          method: 'POST',
          body: formData
        });
      },

      getFeed: function(params) {
        const query = new URLSearchParams(params).toString();
        return window.iNodesAPI.request('/api/posts?' + query);
      },

      like: function(postId) {
        return window.iNodesAPI.request('/api/posts/' + postId + '/like', {
          method: 'POST'
        });
      },

      comment: function(postId, text) {
        return window.iNodesAPI.request('/api/posts/' + postId + '/comment', {
          method: 'POST',
          body: { text: text }
        });
      },

      delete: function(postId) {
        return window.iNodesAPI.request('/api/posts/' + postId, {
          method: 'DELETE'
        });
      }
    },

    // Story endpoints
    stories: {
      create: function(formData) {
        return window.iNodesAPI.request('/api/stories', {
          method: 'POST',
          body: formData
        });
      },

      getAll: function() {
        return window.iNodesAPI.request('/api/stories');
      },

      view: function(storyId) {
        return window.iNodesAPI.request('/api/stories/' + storyId + '/view', {
          method: 'POST'
        });
      }
    },

    // Chat endpoints
    chats: {
      create: function(data) {
        return window.iNodesAPI.request('/api/chats', {
          method: 'POST',
          body: data
        });
      },

      getAll: function() {
        return window.iNodesAPI.request('/api/chats');
      },

      getMessages: function(chatId, params) {
        const query = params ? '?' + new URLSearchParams(params).toString() : '';
        return window.iNodesAPI.request('/api/chats/' + chatId + '/messages' + query);
      }
    },

    // Message endpoints
    messages: {
      send: function(formData) {
        return window.iNodesAPI.request('/api/messages', {
          method: 'POST',
          body: formData
        });
      },

      markRead: function(messageId) {
        return window.iNodesAPI.request('/api/messages/' + messageId + '/read', {
          method: 'POST'
        });
      },

      react: function(messageId, reaction) {
        return window.iNodesAPI.request('/api/messages/' + messageId + '/react', {
          method: 'POST',
          body: { reaction: reaction }
        });
      },

      edit: function(messageId, content) {
        return window.iNodesAPI.request('/api/messages/' + messageId, {
          method: 'PUT',
          body: { content: content }
        });
      },

      delete: function(messageId) {
        return window.iNodesAPI.request('/api/messages/' + messageId, {
          method: 'DELETE'
        });
      }
    },

    // Notification endpoints
    notifications: {
      getAll: function(params) {
        const query = params ? '?' + new URLSearchParams(params).toString() : '';
        return window.iNodesAPI.request('/api/notifications' + query);
      },

      markRead: function(notificationId) {
        return window.iNodesAPI.request('/api/notifications/' + notificationId + '/read', {
          method: 'PUT'
        });
      }
    },

    // Search endpoint
    search: function(params) {
      const query = new URLSearchParams(params).toString();
      return window.iNodesAPI.request('/api/search?' + query);
    }
  };

  // ============================================================================
  // AUTHENTICATION
  // ============================================================================

  window.iNodesAuth = {
    // Initialize auth state
    init: function() {
      const accessToken = window.iNodesStorage.get('accessToken');
      const refreshToken = window.iNodesStorage.get('refreshToken');
      const deviceId = window.iNodesStorage.get('deviceId');
      const user = window.iNodesStorage.get('user');

      if (accessToken && refreshToken && deviceId) {
        window.iNodesApp.accessToken = accessToken;
        window.iNodesApp.refreshToken = refreshToken;
        window.iNodesApp.deviceId = deviceId;
        window.iNodesApp.user = user;
        window.iNodesApp.isAuthenticated = true;

        window.iNodesAuth.verifySession();
      } else {
        window.iNodesAuth.showAuthScreen();
      }
    },

    // Verify session
    verifySession: async function() {
      try {
        const user = await window.iNodesAPI.users.getMe();
        window.iNodesApp.user = user;
        window.iNodesStorage.set('user', user);
        window.iNodesAuth.showMainApp();
      } catch (error) {
        console.error('Session verification failed:', error);
        window.iNodesUtils.showToast('Please login again', 'warning');
        window.iNodesAuth.logout();
      }
    },

    // Register
    register: async function(userData) {
      try {
        const deviceId = window.iNodesUtils.generateDeviceId();
        userData.deviceId = deviceId;

        const data = await window.iNodesAPI.auth.register(userData);

        window.iNodesApp.user = data.user;
        window.iNodesApp.accessToken = data.accessToken;
        window.iNodesApp.refreshToken = data.refreshToken;
        window.iNodesApp.deviceId = deviceId;
        window.iNodesApp.isAuthenticated = true;

        window.iNodesStorage.set('user', data.user);
        window.iNodesStorage.set('accessToken', data.accessToken);
        window.iNodesStorage.set('refreshToken', data.refreshToken);
        window.iNodesStorage.set('deviceId', deviceId);

        window.iNodesUtils.showToast('Account created successfully!', 'success');
        window.iNodesAuth.showMainApp();
      } catch (error) {
        window.iNodesUtils.showToast(error.message, 'error');
        throw error;
      }
    },

    // Login
    login: async function(credentials) {
      try {
        let deviceId = window.iNodesStorage.get('deviceId');
        if (!deviceId) {
          deviceId = window.iNodesUtils.generateDeviceId();
        }
        credentials.deviceId = deviceId;

        const data = await window.iNodesAPI.auth.login(credentials);

        window.iNodesApp.user = data.user;
        window.iNodesApp.accessToken = data.accessToken;
        window.iNodesApp.refreshToken = data.refreshToken;
        window.iNodesApp.deviceId = deviceId;
        window.iNodesApp.isAuthenticated = true;

        window.iNodesStorage.set('user', data.user);
        window.iNodesStorage.set('accessToken', data.accessToken);
        window.iNodesStorage.set('refreshToken', data.refreshToken);
        window.iNodesStorage.set('deviceId', deviceId);

        window.iNodesUtils.showToast('Welcome back!', 'success');
        window.iNodesAuth.showMainApp();
      } catch (error) {
        window.iNodesUtils.showToast(error.message, 'error');
        throw error;
      }
    },

    // Logout
    logout: async function() {
      try {
        await window.iNodesAPI.auth.logout();
      } catch (error) {
        console.error('Logout error:', error);
      }

      if (window.iNodesApp.socket) {
        try {
          window.iNodesApp.socket.disconnect();
        } catch (e) {
          console.error('Socket disconnect error:', e);
        }
        window.iNodesApp.socket = null;
      }

      window.iNodesApp.user = null;
      window.iNodesApp.accessToken = null;
      window.iNodesApp.refreshToken = null;
      window.iNodesApp.isAuthenticated = false;

      window.iNodesStorage.clear();

      window.iNodesAuth.showAuthScreen();
      window.iNodesUtils.showToast('Logged out successfully', 'info');
    },

    // Show auth screen
    showAuthScreen: function() {
      document.getElementById('auth-screen').style.display = 'flex';
      document.getElementById('main-app').style.display = 'none';
    },

    // Show main app
    showMainApp: function() {
      document.getElementById('auth-screen').style.display = 'none';
      document.getElementById('main-app').style.display = 'flex';

      if (typeof window.iNodesUI !== 'undefined' && window.iNodesUI.initMainApp) {
        window.iNodesUI.initMainApp();
      }
      
      if (typeof window.iNodesSocket !== 'undefined' && window.iNodesSocket.connect) {
        window.iNodesSocket.connect();
      }
    }
  };

  // Export socket URL for socket.js
  window.iNodesConfig = {
    SOCKET_URL: SOCKET_URL
  };

  // ============================================================================
  // INITIALIZATION
  // ============================================================================

  function initialize() {
    console.log('iNodes App Initializing...');
    window.iNodesAuth.init();
    
    if (typeof window.iNodesUI !== 'undefined' && window.iNodesUI.initAuthForms) {
      window.iNodesUI.initAuthForms();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
  } else {
    initialize();
  }

})();