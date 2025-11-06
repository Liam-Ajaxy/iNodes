// ============================================================================
// iNodes Frontend - Socket.IO Real-time Communication
// Pure JavaScript - CSP Compliant
// ============================================================================

(function() {
  'use strict';

  // ============================================================================
  // SOCKET.IO CLIENT
  // ============================================================================

  window.iNodesSocket = {
    socket: null,
    reconnectAttempts: 0,
    maxReconnectAttempts: 5,
    typingTimeout: null,

    // Connect to Socket.IO server
    connect: function() {
      if (window.iNodesApp.socket) {
        return; // Already connected
      }

      // Check if io is available
      if (typeof io === 'undefined') {
        console.error('Socket.IO library not loaded! Add: <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>');
        window.iNodesUtils.showToast('Socket.IO not loaded', 'error');
        return;
      }

      try {
        const socketUrl = window.iNodesConfig ? window.iNodesConfig.SOCKET_URL : window.location.origin;
        console.log('Connecting to Socket.IO:', socketUrl);

        // Initialize Socket.IO connection
        window.iNodesApp.socket = io(socketUrl, {
          transports: ['websocket', 'polling'],
          reconnection: true,
          reconnectionAttempts: window.iNodesSocket.maxReconnectAttempts,
          reconnectionDelay: 1000,
          reconnectionDelayMax: 5000
        });

        window.iNodesSocket.socket = window.iNodesApp.socket;

        // Setup event listeners
        window.iNodesSocket.setupListeners();

        // Authenticate socket connection
        window.iNodesSocket.authenticate();
      } catch (error) {
        console.error('Socket connection error:', error);
        window.iNodesUtils.showToast('Connection error', 'error');
      }
    },

    // Authenticate socket
    authenticate: function() {
      if (!window.iNodesApp.accessToken) {
        console.error('No access token for socket auth');
        return;
      }

      // Verify token is not expired before sending
      try {
        const tokenParts = window.iNodesApp.accessToken.split('.');
        if (tokenParts.length === 3) {
          const payload = JSON.parse(atob(tokenParts[1]));
          const exp = payload.exp * 1000; // Convert to milliseconds
          
          if (Date.now() >= exp) {
            console.log('Access token expired, refreshing before socket auth...');
            window.iNodesAPI.refreshAccessToken().then(function(success) {
              if (success && window.iNodesSocket.socket) {
                window.iNodesSocket.socket.emit('socket_auth', {
                  token: window.iNodesApp.accessToken
                });
              }
            }).catch(function(err) {
              console.error('Token refresh failed:', err);
              window.iNodesUtils.showToast('Session expired, please login again', 'warning');
              setTimeout(function() {
                window.iNodesAuth.logout();
              }, 2000);
            });
            return;
          }
        }
      } catch (e) {
        console.error('Token validation error:', e);
      }

      window.iNodesSocket.socket.emit('socket_auth', {
        token: window.iNodesApp.accessToken
      });
    },

    // Setup all socket event listeners
    setupListeners: function() {
      const socket = window.iNodesSocket.socket;

      // Connection events
      socket.on('connect', function() {
        console.log('Socket connected:', socket.id);
        window.iNodesSocket.reconnectAttempts = 0;
        window.iNodesSocket.updateConnectionStatus(true);
        window.iNodesSocket.authenticate();
      });

      socket.on('disconnect', function(reason) {
        console.log('Socket disconnected:', reason);
        window.iNodesSocket.updateConnectionStatus(false);
      });

      socket.on('connect_error', function(error) {
        console.error('Socket connection error:', error);
        window.iNodesSocket.reconnectAttempts++;
        
        if (window.iNodesSocket.reconnectAttempts >= window.iNodesSocket.maxReconnectAttempts) {
          window.iNodesUtils.showToast('Connection lost. Please refresh.', 'error');
        }
      });

      socket.on('reconnect', function(attemptNumber) {
        console.log('Socket reconnected after', attemptNumber, 'attempts');
        window.iNodesUtils.showToast('Reconnected', 'success');
      });

      // Auth events
      socket.on('auth_success', function(data) {
        console.log('Socket authenticated for user:', data.userId);
        window.iNodesSocket.startPresencePing();
      });

      socket.on('auth_error', function(data) {
        console.error('Socket auth error:', data.error);
        window.iNodesUtils.showToast('Authentication error', 'error');
      });

      // Message events
      socket.on('receive_message', function(message) {
        window.iNodesSocket.handleReceiveMessage(message);
      });

      socket.on('message_status_update', function(data) {
        window.iNodesSocket.handleMessageStatusUpdate(data);
      });

      socket.on('message_reaction', function(data) {
        window.iNodesSocket.handleMessageReaction(data);
      });

      socket.on('message_edited', function(data) {
        window.iNodesSocket.handleMessageEdited(data);
      });

      socket.on('message_deleted', function(data) {
        window.iNodesSocket.handleMessageDeleted(data);
      });

      // Typing indicator
      socket.on('user_typing', function(data) {
        window.iNodesSocket.handleUserTyping(data);
      });

      // Chat events
      socket.on('chat_created', function(data) {
        window.iNodesSocket.handleChatCreated(data);
      });

      socket.on('chat_updated', function(data) {
        window.iNodesSocket.handleChatUpdated(data);
      });

      socket.on('removed_from_chat', function(data) {
        window.iNodesSocket.handleRemovedFromChat(data);
      });

      // Notification events
      socket.on('notification', function(data) {
        window.iNodesSocket.handleNotification(data);
      });

      // Post/Story events
      socket.on('post_created', function(data) {
        window.iNodesSocket.handlePostCreated(data);
      });

      socket.on('story_added', function(data) {
        window.iNodesSocket.handleStoryAdded(data);
      });

      socket.on('story_view', function(data) {
        window.iNodesSocket.handleStoryView(data);
      });

      // Presence events
      socket.on('user_online', function(data) {
        window.iNodesSocket.handleUserOnline(data);
      });

      socket.on('user_offline', function(data) {
        window.iNodesSocket.handleUserOffline(data);
      });

      // Error event
      socket.on('error', function(data) {
        console.error('Socket error:', data);
        window.iNodesUtils.showToast(data.error || 'An error occurred', 'error');
      });
    },

    // Update connection status indicator
    updateConnectionStatus: function(isOnline) {
      const indicator = document.getElementById('connection-indicator');
      if (!indicator) return;

      if (isOnline) {
        indicator.className = 'online';
        indicator.textContent = 'Online';
      } else {
        indicator.className = 'offline';
        indicator.textContent = 'Offline';
      }
    },

    // Start presence ping
    startPresencePing: function() {
      // Ping every 30 seconds
      setInterval(function() {
        if (window.iNodesSocket.socket && window.iNodesSocket.socket.connected) {
          window.iNodesSocket.socket.emit('presence_ping', {});
        }
      }, 30000);
    },

    // ============================================================================
    // MESSAGE EVENT HANDLERS
    // ============================================================================

    handleReceiveMessage: function(message) {
      console.log('Received message:', message);

      // Update chat list if exists
      if (typeof window.iNodesUI.updateChatInList === 'function') {
        window.iNodesUI.updateChatInList(message.chat);
      }

      // If viewing this chat, append message
      if (window.iNodesApp.currentChat && window.iNodesApp.currentChat === message.chat.toString()) {
        if (typeof window.iNodesUI.appendMessage === 'function') {
          window.iNodesUI.appendMessage(message);
        }

        // Mark as delivered
        window.iNodesSocket.socket.emit('message_delivered', {
          chatId: message.chat,
          messageId: message._id
        });

        // Mark as read if window is focused
        if (document.hasFocus()) {
          window.iNodesAPI.messages.markRead(message._id).catch(function(err) {
            console.error('Mark read error:', err);
          });
        }
      } else {
        // Show notification and update badge
        window.iNodesSocket.showMessageNotification(message);
        window.iNodesApp.unreadCounts.messages++;
        window.iNodesSocket.updateBadge('messages', window.iNodesApp.unreadCounts.messages);
      }

      // Play notification sound
      window.iNodesSocket.playNotificationSound();
    },

    handleMessageStatusUpdate: function(data) {
      console.log('Message status update:', data);
      
      if (typeof window.iNodesUI.updateMessageStatus === 'function') {
        window.iNodesUI.updateMessageStatus(data.messageId, data.status);
      }
    },

    handleMessageReaction: function(data) {
      console.log('Message reaction:', data);
      
      if (typeof window.iNodesUI.updateMessageReactions === 'function') {
        window.iNodesUI.updateMessageReactions(data.messageId, data.reactions);
      }
    },

    handleMessageEdited: function(data) {
      console.log('Message edited:', data);
      
      if (typeof window.iNodesUI.updateMessageContent === 'function') {
        window.iNodesUI.updateMessageContent(data.messageId, data.decryptedContent);
      }
    },

    handleMessageDeleted: function(data) {
      console.log('Message deleted:', data);
      
      if (typeof window.iNodesUI.removeMessage === 'function') {
        window.iNodesUI.removeMessage(data.messageId);
      }
    },

    // ============================================================================
    // TYPING INDICATOR
    // ============================================================================

    handleUserTyping: function(data) {
      if (window.iNodesApp.currentChat !== data.chatId) return;

      const indicator = document.getElementById('typing-indicator');
      if (!indicator) return;

      if (data.isTyping) {
        indicator.style.display = 'block';
      } else {
        indicator.style.display = 'none';
      }
    },

    sendTypingIndicator: function(chatId, isTyping) {
      if (window.iNodesSocket.socket && window.iNodesSocket.socket.connected) {
        window.iNodesSocket.socket.emit('typing', {
          chatId: chatId,
          isTyping: isTyping
        });
      }
    },

    // ============================================================================
    // CHAT EVENT HANDLERS
    // ============================================================================

    handleChatCreated: function(data) {
      console.log('Chat created:', data.chat);
      
      if (typeof window.iNodesUI.prependChatToList === 'function') {
        window.iNodesUI.prependChatToList(data.chat);
      }
    },

    handleChatUpdated: function(data) {
      console.log('Chat updated:', data.chat);
      
      if (typeof window.iNodesUI.updateChatInList === 'function') {
        window.iNodesUI.updateChatInList(data.chat);
      }
    },

    handleRemovedFromChat: function(data) {
      console.log('Removed from chat:', data.chatId);
      
      window.iNodesUtils.showToast('You were removed from a chat', 'warning');
      
      if (typeof window.iNodesUI.removeChatFromList === 'function') {
        window.iNodesUI.removeChatFromList(data.chatId);
      }

      // If currently viewing this chat, close it
      if (window.iNodesApp.currentChat === data.chatId) {
        if (typeof window.iNodesUI.closeActiveChat === 'function') {
          window.iNodesUI.closeActiveChat();
        }
      }
    },

    // ============================================================================
    // NOTIFICATION HANDLERS
    // ============================================================================

    handleNotification: function(data) {
      console.log('Notification received:', data);

      // Update notification badge
      window.iNodesApp.unreadCounts.notifications++;
      window.iNodesSocket.updateBadge('notifications', window.iNodesApp.unreadCounts.notifications);

      // Show toast based on type
      let message = '';
      switch (data.type) {
        case 'like':
          message = 'Someone liked your post';
          break;
        case 'comment':
          message = 'Someone commented on your post';
          break;
        case 'follow':
          message = 'You have a new follower';
          break;
        case 'mention':
          message = 'You were mentioned in a post';
          break;
        default:
          message = 'New notification';
      }

      window.iNodesUtils.showToast(message, 'info');
      window.iNodesSocket.playNotificationSound();

      // Update notifications list if viewing
      if (window.iNodesApp.currentView === 'notifications') {
        if (typeof window.iNodesUI.loadNotifications === 'function') {
          window.iNodesUI.loadNotifications();
        }
      }
    },

    // ============================================================================
    // POST/STORY HANDLERS
    // ============================================================================

    handlePostCreated: function(data) {
      console.log('Post created:', data.post);

      // Prepend to feed if on home view
      if (window.iNodesApp.currentView === 'feed') {
        if (typeof window.iNodesUI.prependPostToFeed === 'function') {
          window.iNodesUI.prependPostToFeed(data.post);
        }
      }
    },

    handleStoryAdded: function(data) {
      console.log('Story added:', data.story);

      // Update stories bar
      if (typeof window.iNodesUI.updateStoriesBar === 'function') {
        window.iNodesUI.updateStoriesBar();
      }
    },

    handleStoryView: function(data) {
      console.log('Story view:', data);
      // Could update viewer count if story modal is open
    },

    // ============================================================================
    // PRESENCE HANDLERS
    // ============================================================================

    handleUserOnline: function(data) {
      console.log('User online:', data.userId);
      
      if (typeof window.iNodesUI.updateUserPresence === 'function') {
        window.iNodesUI.updateUserPresence(data.userId, true);
      }
    },

    handleUserOffline: function(data) {
      console.log('User offline:', data.userId);
      
      if (typeof window.iNodesUI.updateUserPresence === 'function') {
        window.iNodesUI.updateUserPresence(data.userId, false, data.lastSeen);
      }
    },

    // ============================================================================
    // UTILITY FUNCTIONS
    // ============================================================================

    updateBadge: function(type, count) {
      const badge = document.getElementById(type + '-badge');
      if (!badge) return;

      if (count > 0) {
        badge.textContent = count > 99 ? '99+' : count.toString();
        badge.style.display = 'inline-block';
      } else {
        badge.style.display = 'none';
      }
    },

    showMessageNotification: function(message) {
      // Could implement browser notifications here
      const sender = message.sender.displayName || message.sender.username;
      const preview = message.decryptedContent.substring(0, 50);
      window.iNodesUtils.showToast(sender + ': ' + preview, 'info');
    },

    playNotificationSound: function() {
      // Simple notification sound using Web Audio API
      try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);

        oscillator.frequency.value = 800;
        oscillator.type = 'sine';

        gainNode.gain.value = 0.1;
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.1);

        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.1);
      } catch (error) {
        // Silently fail if audio not supported
      }
    },

    // ============================================================================
    // SOCKET EMITTERS
    // ============================================================================

    joinChat: function(chatId) {
      if (window.iNodesSocket.socket && window.iNodesSocket.socket.connected) {
        window.iNodesSocket.socket.emit('join_chat', { chatId: chatId });
      }
    },

    leaveChat: function(chatId) {
      if (window.iNodesSocket.socket && window.iNodesSocket.socket.connected) {
        window.iNodesSocket.socket.emit('leave_chat', { chatId: chatId });
      }
    },

    // Disconnect socket
    disconnect: function() {
      if (window.iNodesSocket.socket) {
        window.iNodesSocket.socket.disconnect();
        window.iNodesSocket.socket = null;
        window.iNodesApp.socket = null;
      }
    }
  };

})();