// ============================================================================
// iNodes Frontend - UI Handlers & DOM Manipulation
// Pure JavaScript - CSP Compliant
// ============================================================================

(function() {
  'use strict';

  // ============================================================================
  // UI CONTROLLER
  // ============================================================================

  window.iNodesUI = {
    currentFeedType: 'home',
    currentPage: 1,
    isLoadingPosts: false,

    // ============================================================================
    // AUTH FORMS
    // ============================================================================

    initAuthForms: function() {
      // Add clear storage button for debugging
      const loginForm = document.getElementById('login-form');
      if (loginForm && !document.getElementById('clear-storage-btn')) {
        const clearBtn = document.createElement('button');
        clearBtn.id = 'clear-storage-btn';
        clearBtn.type = 'button';
        clearBtn.className = 'btn btn-secondary btn-sm';
        clearBtn.textContent = 'Clear Old Session';
        clearBtn.style.marginTop = '10px';
        clearBtn.addEventListener('click', function() {
          window.iNodesStorage.clear();
          window.iNodesUtils.showToast('Storage cleared. Please login again.', 'success');
          window.location.reload();
        });
        loginForm.appendChild(clearBtn);
      }

      // Login form
      const loginFormElement = document.getElementById('login-form-element');
      if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
          e.preventDefault();
          
          const username = document.getElementById('login-username').value.trim();
          const password = document.getElementById('login-password').value;

          if (!username || !password) {
            window.iNodesUtils.showToast('Please fill all fields', 'error');
            return;
          }

          window.iNodesAuth.login({
            usernameOrEmail: username,
            password: password
          }).catch(function(error) {
            console.error('Login error:', error);
          });
        });
      }

      // Register form
      const registerForm = document.getElementById('register-form-element');
      if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
          e.preventDefault();
          
          const username = document.getElementById('register-username').value.trim();
          const email = document.getElementById('register-email').value.trim();
          const displayName = document.getElementById('register-displayname').value.trim();
          const password = document.getElementById('register-password').value;

          // Validation
          if (!username || !email || !password) {
            window.iNodesUtils.showToast('Please fill all required fields', 'error');
            return;
          }

          if (!window.iNodesUtils.validateUsername(username)) {
            window.iNodesUtils.showToast('Invalid username format', 'error');
            return;
          }

          if (!window.iNodesUtils.validateEmail(email)) {
            window.iNodesUtils.showToast('Invalid email format', 'error');
            return;
          }

          if (!window.iNodesUtils.validatePassword(password)) {
            window.iNodesUtils.showToast('Password must be 8+ chars with letter and number', 'error');
            return;
          }

          window.iNodesAuth.register({
            username: username,
            email: email,
            displayName: displayName || username,
            password: password
          }).catch(function(error) {
            console.error('Register error:', error);
          });
        });
      }

      // Toggle forms
      const showRegisterLink = document.getElementById('show-register-link');
      const showLoginLink = document.getElementById('show-login-link');

      if (showRegisterLink) {
        showRegisterLink.addEventListener('click', function(e) {
          e.preventDefault();
          document.getElementById('login-form').style.display = 'none';
          document.getElementById('register-form').style.display = 'block';
        });
      }

      if (showLoginLink) {
        showLoginLink.addEventListener('click', function(e) {
          e.preventDefault();
          document.getElementById('register-form').style.display = 'none';
          document.getElementById('login-form').style.display = 'block';
        });
      }
    },

    // ============================================================================
    // MAIN APP INITIALIZATION
    // ============================================================================

    initMainApp: function() {
      // Setup navigation
      window.iNodesUI.setupNavigation();

      // Setup logout button
      const logoutBtn = document.getElementById('logout-btn');
      if (logoutBtn) {
        logoutBtn.addEventListener('click', function() {
          if (confirm('Are you sure you want to logout?')) {
            window.iNodesAuth.logout();
          }
        });
      }

      // Setup create post button
      const createPostBtn = document.getElementById('create-post-btn');
      if (createPostBtn) {
        createPostBtn.addEventListener('click', function() {
          window.iNodesUI.showCreatePostModal();
        });
      }

      // Setup create story button
      const createStoryBtn = document.getElementById('create-story-btn');
      if (createStoryBtn) {
        createStoryBtn.addEventListener('click', function() {
          window.iNodesUI.showCreateStoryModal();
        });
      }

      // Setup new chat button
      const newChatBtn = document.getElementById('new-chat-btn');
      if (newChatBtn) {
        newChatBtn.addEventListener('click', function() {
          window.iNodesUI.showNewChatModal();
        });
      }

      // Load initial view
      window.iNodesUI.loadFeed();
      window.iNodesUI.loadChats();
      window.iNodesUI.loadStories();
      window.iNodesUI.loadProfile();
    },

    // ============================================================================
    // NAVIGATION
    // ============================================================================

    setupNavigation: function() {
      const navLinks = document.querySelectorAll('.nav-link');
      
      navLinks.forEach(function(link) {
        link.addEventListener('click', function(e) {
          e.preventDefault();
          
          const view = this.getAttribute('data-view');
          window.iNodesUI.switchView(view);
          
          // Update active state
          navLinks.forEach(function(l) { l.classList.remove('active'); });
          this.classList.add('active');
        });
      });

      // Feed tabs
      const feedTabs = document.querySelectorAll('.tab-btn[data-feed-type]');
      feedTabs.forEach(function(tab) {
        tab.addEventListener('click', function() {
          const feedType = this.getAttribute('data-feed-type');
          window.iNodesUI.currentFeedType = feedType;
          
          feedTabs.forEach(function(t) { t.classList.remove('active'); });
          this.classList.add('active');
          
          window.iNodesUI.loadFeed();
        });
      });
    },

    switchView: function(viewName) {
      window.iNodesApp.currentView = viewName;
      
      // Hide all views
      const views = document.querySelectorAll('.view');
      views.forEach(function(view) {
        view.classList.remove('active');
      });

      // Show selected view
      const selectedView = document.getElementById(viewName + '-view');
      if (selectedView) {
        selectedView.classList.add('active');
      }

      // Load view-specific data
      switch (viewName) {
        case 'feed':
        case 'explore':
          window.iNodesUI.loadFeed();
          break;
        case 'messages':
          window.iNodesUI.loadChats();
          break;
        case 'notifications':
          window.iNodesUI.loadNotifications();
          break;
        case 'profile':
          window.iNodesUI.loadProfile();
          break;
      }
    },

    // ============================================================================
    // FEED/POSTS
    // ============================================================================

    loadFeed: function() {
      if (window.iNodesUI.isLoadingPosts) return;
      
      window.iNodesUI.isLoadingPosts = true;
      const container = document.getElementById('posts-container');
      if (!container) return;

      container.innerHTML = '<div class="loading">Loading posts...</div>';

      const params = {
        page: 1,
        limit: 20,
        feedType: window.iNodesUI.currentFeedType
      };

      window.iNodesAPI.posts.getFeed(params)
        .then(function(data) {
          window.iNodesUI.renderPosts(data.posts);
          window.iNodesUI.isLoadingPosts = false;
        })
        .catch(function(error) {
          console.error('Load feed error:', error);
          container.innerHTML = '<div class="error">Failed to load posts</div>';
          window.iNodesUI.isLoadingPosts = false;
        });
    },

    renderPosts: function(posts) {
      const container = document.getElementById('posts-container');
      if (!container) return;

      if (!posts || posts.length === 0) {
        container.innerHTML = '<div class="empty-state"><span class="icon">📭</span><p>No posts to show</p></div>';
        return;
      }

      container.innerHTML = '';
      
      posts.forEach(function(post) {
        const postEl = window.iNodesUI.createPostElement(post);
        container.appendChild(postEl);
      });
    },

    createPostElement: function(post) {
      const article = document.createElement('article');
      article.className = 'post';
      article.setAttribute('data-post-id', post._id);

      const author = post.author;
      const isLiked = post.isLiked || false;
      const likesCount = post.likesCount || 0;
      const commentsCount = post.commentsCount || post.comments?.length || 0;

      let mediaHtml = '';
      if (post.media && post.media.length > 0) {
        const media = post.media[0];
        if (media.type === 'video') {
          mediaHtml = '<div class="post-media"><video class="post-image" controls src="' + 
                      window.iNodesUtils.escapeHtml(media.url) + '"></video></div>';
        } else {
          mediaHtml = '<div class="post-media"><img class="post-image" src="' + 
                      window.iNodesUtils.escapeHtml(media.url) + '" alt="Post image"></div>';
        }
      }

      const avatarUrl = (author.avatar && author.avatar.url) ? author.avatar.url : window.iNodesUtils.getDefaultAvatar();

      article.innerHTML = 
        '<div class="post-header">' +
          '<img src="' + avatarUrl + '" alt="Avatar" class="avatar">' +
          '<div class="post-author-info">' +
            '<strong>' + window.iNodesUtils.escapeHtml(author.displayName || author.username) + '</strong>' +
            (author.isVerified ? '<span class="verified">✓</span>' : '') +
            '<p class="text-muted">@' + window.iNodesUtils.escapeHtml(author.username) + ' · ' + 
            window.iNodesUtils.formatDate(post.createdAt) + '</p>' +
          '</div>' +
        '</div>' +
        mediaHtml +
        '<div class="post-content">' +
          '<p>' + window.iNodesUtils.escapeHtml(post.caption || '') + '</p>' +
        '</div>' +
        '<div class="post-actions">' +
          '<button class="btn btn-icon like-btn ' + (isLiked ? 'active' : '') + '" data-post-id="' + post._id + '">' +
            (isLiked ? '❤️' : '🤍') + ' <span class="likes-count">' + likesCount + '</span>' +
          '</button>' +
          '<button class="btn btn-icon comment-btn" data-post-id="' + post._id + '">' +
            '💬 ' + commentsCount +
          '</button>' +
          '<button class="btn btn-icon share-btn">' +
            '📤' +
          '</button>' +
        '</div>';

      // Attach event listeners
      const likeBtn = article.querySelector('.like-btn');
      if (likeBtn) {
        likeBtn.addEventListener('click', function() {
          window.iNodesUI.toggleLike(post._id, this);
        });
      }

      const commentBtn = article.querySelector('.comment-btn');
      if (commentBtn) {
        commentBtn.addEventListener('click', function() {
          window.iNodesUI.showPostModal(post._id);
        });
      }

      return article;
    },

    toggleLike: function(postId, buttonEl) {
      window.iNodesAPI.posts.like(postId)
        .then(function(data) {
          const likesCountEl = buttonEl.querySelector('.likes-count');
          if (likesCountEl) {
            likesCountEl.textContent = data.likesCount;
          }
          
          if (data.liked) {
            buttonEl.classList.add('active');
            buttonEl.innerHTML = '❤️ <span class="likes-count">' + data.likesCount + '</span>';
          } else {
            buttonEl.classList.remove('active');
            buttonEl.innerHTML = '🤍 <span class="likes-count">' + data.likesCount + '</span>';
          }
        })
        .catch(function(error) {
          console.error('Like error:', error);
          window.iNodesUtils.showToast('Failed to like post', 'error');
        });
    },

    prependPostToFeed: function(post) {
      const container = document.getElementById('posts-container');
      if (!container) return;

      const emptyState = container.querySelector('.empty-state');
      if (emptyState) {
        container.innerHTML = '';
      }

      const postEl = window.iNodesUI.createPostElement(post);
      container.insertBefore(postEl, container.firstChild);
    },

    // ============================================================================
    // MESSAGES/CHATS
    // ============================================================================

    loadChats: function() {
      const container = document.getElementById('chats-list');
      if (!container) return;

      container.innerHTML = '<div class="loading">Loading chats...</div>';

      window.iNodesAPI.chats.getAll()
        .then(function(chats) {
          window.iNodesUI.renderChats(chats);
        })
        .catch(function(error) {
          console.error('Load chats error:', error);
          container.innerHTML = '<div class="error">Failed to load chats</div>';
        });
    },

    renderChats: function(chats) {
      const container = document.getElementById('chats-list');
      if (!container) return;

      if (!chats || chats.length === 0) {
        container.innerHTML = '<div class="empty-state">No chats yet</div>';
        return;
      }

      container.innerHTML = '';
      
      chats.forEach(function(chat) {
        const chatEl = window.iNodesUI.createChatElement(chat);
        container.appendChild(chatEl);
      });
    },

    createChatElement: function(chat) {
      const div = document.createElement('div');
      div.className = 'chat-item';
      div.setAttribute('data-chat-id', chat._id);

      // Get chat display info
      let displayName = '';
      let avatarUrl = window.iNodesUtils.getDefaultAvatar();
      
      if (chat.isGroup) {
        displayName = chat.name || 'Group Chat';
      } else {
        // Find other participant
        const otherUser = chat.participants.find(function(p) {
          return p.userId && p.userId._id !== window.iNodesApp.user._id;
        });
        if (otherUser && otherUser.userId) {
          displayName = otherUser.userId.displayName || otherUser.userId.username;
          avatarUrl = (otherUser.userId.avatar && otherUser.userId.avatar.url) ? otherUser.userId.avatar.url : avatarUrl;
        }
      }

      const lastMessage = chat.lastMessage?.decryptedContent || 'No messages yet';
      const lastMessageTime = chat.lastMessage?.createdAt 
        ? window.iNodesUtils.formatDate(chat.lastMessage.createdAt) 
        : '';

      div.innerHTML = 
        '<img src="' + avatarUrl + '" alt="Avatar" class="avatar">' +
        '<div class="chat-item-info">' +
          '<strong>' + window.iNodesUtils.escapeHtml(displayName) + '</strong>' +
          '<p class="text-muted">' + window.iNodesUtils.escapeHtml(lastMessage.substring(0, 50)) + '</p>' +
        '</div>' +
        '<span class="text-muted">' + lastMessageTime + '</span>';

      div.addEventListener('click', function() {
        window.iNodesUI.openChat(chat._id);
      });

      return div;
    },

    openChat: function(chatId) {
      // Update UI
      const chatItems = document.querySelectorAll('.chat-item');
      chatItems.forEach(function(item) {
        item.classList.remove('active');
      });

      const selectedChat = document.querySelector('.chat-item[data-chat-id="' + chatId + '"]');
      if (selectedChat) {
        selectedChat.classList.add('active');
      }

      // Show active chat
      document.getElementById('no-chat-selected').style.display = 'none';
      document.getElementById('active-chat').style.display = 'flex';

      // Leave previous chat
      if (window.iNodesApp.currentChat) {
        window.iNodesSocket.leaveChat(window.iNodesApp.currentChat);
      }

      // Set current chat
      window.iNodesApp.currentChat = chatId;

      // Join socket room
      window.iNodesSocket.joinChat(chatId);

      // Load messages
      window.iNodesUI.loadMessages(chatId);

      // Setup message form
      window.iNodesUI.setupMessageForm(chatId);
    },

    loadMessages: function(chatId) {
      const container = document.getElementById('messages-container');
      if (!container) return;

      container.innerHTML = '<div class="loading">Loading messages...</div>';

      window.iNodesAPI.chats.getMessages(chatId, { limit: 50 })
        .then(function(messages) {
          window.iNodesUI.renderMessages(messages);
          container.scrollTop = container.scrollHeight;
        })
        .catch(function(error) {
          console.error('Load messages error:', error);
          container.innerHTML = '<div class="error">Failed to load messages</div>';
        });
    },

    renderMessages: function(messages) {
      const container = document.getElementById('messages-container');
      if (!container) return;

      container.innerHTML = '';

      if (!messages || messages.length === 0) {
        container.innerHTML = '<div class="empty-state">No messages yet</div>';
        return;
      }

      messages.forEach(function(message) {
        const messageEl = window.iNodesUI.createMessageElement(message);
        container.appendChild(messageEl);
      });
    },

    createMessageElement: function(message) {
      const div = document.createElement('div');
      const isOwn = message.sender._id === window.iNodesApp.user._id;
      
      div.className = 'message' + (isOwn ? ' message-own' : '');
      div.setAttribute('data-message-id', message._id);

      const senderName = message.sender.displayName || message.sender.username;
      const content = message.decryptedContent || '[Unable to decrypt]';
      const time = window.iNodesUtils.formatTime(message.createdAt);
      const avatarUrl = (message.sender.avatar && message.sender.avatar.url) ? message.sender.avatar.url : window.iNodesUtils.getDefaultAvatar();

      let reactionsHtml = '';
      if (message.reactions && message.reactions.length > 0) {
        reactionsHtml = '<div class="message-reactions">' +
          message.reactions.map(function(r) { return r.reaction; }).join(' ') +
          '</div>';
      }

      div.innerHTML = 
        '<img src="' + avatarUrl + '" alt="Avatar" class="avatar avatar-sm">' +
        '<div class="message-bubble">' +
          (!isOwn ? '<span class="message-sender">' + window.iNodesUtils.escapeHtml(senderName) + '</span>' : '') +
          '<div>' + window.iNodesUtils.escapeHtml(content) + '</div>' +
          reactionsHtml +
          '<span class="message-time">' + time + '</span>' +
        '</div>';

      return div;
    },

    appendMessage: function(message) {
      const container = document.getElementById('messages-container');
      if (!container) return;

      const emptyState = container.querySelector('.empty-state');
      if (emptyState) {
        container.innerHTML = '';
      }

      const messageEl = window.iNodesUI.createMessageElement(message);
      container.appendChild(messageEl);
      container.scrollTop = container.scrollHeight;
    },

    setupMessageForm: function(chatId) {
      const form = document.getElementById('message-form');
      const input = document.getElementById('message-input');
      
      if (!form || !input) return;

      // Remove old listeners
      const newForm = form.cloneNode(true);
      form.parentNode.replaceChild(newForm, form);

      const newInput = document.getElementById('message-input');

      // Submit handler
      document.getElementById('message-form').addEventListener('submit', function(e) {
        e.preventDefault();
        
        const content = newInput.value.trim();
        if (!content) return;

        const formData = new FormData();
        formData.append('chatId', chatId);
        formData.append('content', content);
        formData.append('idempotencyKey', 'msg_' + Date.now());

        window.iNodesAPI.messages.send(formData)
          .then(function(message) {
            newInput.value = '';
            window.iNodesUI.appendMessage(message);
          })
          .catch(function(error) {
            console.error('Send message error:', error);
            window.iNodesUtils.showToast('Failed to send message', 'error');
          });
      });

      // Typing indicator
      let typingTimeout;
      newInput.addEventListener('input', function() {
        window.iNodesSocket.sendTypingIndicator(chatId, true);
        
        clearTimeout(typingTimeout);
        typingTimeout = setTimeout(function() {
          window.iNodesSocket.sendTypingIndicator(chatId, false);
        }, 1000);
      });
    },

    updateChatInList: function(chatId) {
      // Reload chats to update order
      window.iNodesUI.loadChats();
    },

    prependChatToList: function(chat) {
      const container = document.getElementById('chats-list');
      if (!container) return;

      const emptyState = container.querySelector('.empty-state');
      if (emptyState) {
        container.innerHTML = '';
      }

      const chatEl = window.iNodesUI.createChatElement(chat);
      container.insertBefore(chatEl, container.firstChild);
    },

    // ============================================================================
    // NOTIFICATIONS
    // ============================================================================

    loadNotifications: function() {
      const container = document.getElementById('notifications-container');
      if (!container) return;

      container.innerHTML = '<div class="loading">Loading notifications...</div>';

      window.iNodesAPI.notifications.getAll()
        .then(function(data) {
          window.iNodesUI.renderNotifications(data.notifications);
          
          // Reset unread count
          window.iNodesApp.unreadCounts.notifications = data.unreadCount || 0;
          window.iNodesSocket.updateBadge('notifications', window.iNodesApp.unreadCounts.notifications);
        })
        .catch(function(error) {
          console.error('Load notifications error:', error);
          container.innerHTML = '<div class="error">Failed to load notifications</div>';
        });
    },

    renderNotifications: function(notifications) {
      const container = document.getElementById('notifications-container');
      if (!container) return;

      if (!notifications || notifications.length === 0) {
        container.innerHTML = '<div class="empty-state"><span class="icon">🔔</span><p>No notifications</p></div>';
        return;
      }

      container.innerHTML = '';
      
      notifications.forEach(function(notif) {
        const notifEl = window.iNodesUI.createNotificationElement(notif);
        container.appendChild(notifEl);
      });
    },

    createNotificationElement: function(notif) {
      const div = document.createElement('div');
      div.className = 'notification-item' + (!notif.read ? ' unread' : '');
      div.setAttribute('data-notification-id', notif._id);

      const actor = notif.actor;
      const avatarUrl = (actor && actor.avatar && actor.avatar.url) ? actor.avatar.url : window.iNodesUtils.getDefaultAvatar();
      let message = '';

      switch (notif.type) {
        case 'like':
          message = 'liked your post';
          break;
        case 'comment':
          message = 'commented on your post';
          break;
        case 'follow':
          message = 'started following you';
          break;
        case 'mention':
          message = 'mentioned you in a post';
          break;
        default:
          message = 'notification';
      }

      div.innerHTML = 
        '<img src="' + avatarUrl + '" alt="Avatar" class="avatar">' +
        '<div class="notification-content">' +
          '<p><strong>' + (actor ? window.iNodesUtils.escapeHtml(actor.displayName || actor.username) : 'Someone') + '</strong> ' + message + '</p>' +
          '<span class="text-muted">' + window.iNodesUtils.formatDate(notif.createdAt) + '</span>' +
        '</div>';

      div.addEventListener('click', function() {
        if (!notif.read) {
          window.iNodesAPI.notifications.markRead(notif._id)
            .then(function() {
              div.classList.remove('unread');
              window.iNodesApp.unreadCounts.notifications = Math.max(0, window.iNodesApp.unreadCounts.notifications - 1);
              window.iNodesSocket.updateBadge('notifications', window.iNodesApp.unreadCounts.notifications);
            })
            .catch(function(error) {
              console.error('Mark read error:', error);
            });
        }
      });

      return div;
    },

    // ============================================================================
    // PROFILE
    // ============================================================================

    loadProfile: function() {
      const user = window.iNodesApp.user;
      if (!user) return;

      const avatarUrl = (user.avatar && user.avatar.url) ? user.avatar.url : window.iNodesUtils.getDefaultAvatar();

      // Update profile info
      document.getElementById('profile-avatar').src = avatarUrl;
      document.getElementById('profile-displayname').textContent = user.displayName || user.username;
      document.getElementById('profile-username').textContent = '@' + user.username;
      document.getElementById('profile-bio').textContent = user.bio || 'No bio yet';
      
      document.getElementById('profile-followers').textContent = user.followersCount || 0;
      document.getElementById('profile-following').textContent = user.followingCount || 0;

      // Load user posts
      window.iNodesUI.loadUserPosts(user._id);
    },

    loadUserPosts: function(userId) {
      const container = document.getElementById('profile-content');
      if (!container) return;

      container.innerHTML = '<div class="loading">Loading posts...</div>';

      window.iNodesAPI.posts.getFeed({ feedType: 'user', userId: userId })
        .then(function(data) {
          window.iNodesUI.renderUserPosts(data.posts);
        })
        .catch(function(error) {
          console.error('Load user posts error:', error);
          container.innerHTML = '<div class="error">Failed to load posts</div>';
        });
    },

    renderUserPosts: function(posts) {
      const container = document.getElementById('profile-content');
      if (!container) return;

      if (!posts || posts.length === 0) {
        container.innerHTML = '<div class="empty-state">No posts yet</div>';
        return;
      }

      const grid = document.createElement('div');
      grid.className = 'posts-grid';

      posts.forEach(function(post) {
        if (post.media && post.media.length > 0) {
          const thumbnail = document.createElement('div');
          thumbnail.className = 'post-thumbnail';
          thumbnail.style.backgroundImage = 'url(' + post.media[0].url + ')';
          
          const overlay = document.createElement('div');
          overlay.className = 'post-overlay';
          overlay.innerHTML = '<span>❤️ ' + (post.likesCount || 0) + '</span><span>💬 ' + (post.commentsCount || 0) + '</span>';
          
          thumbnail.appendChild(overlay);
          grid.appendChild(thumbnail);

          thumbnail.addEventListener('click', function() {
            window.iNodesUI.showPostModal(post._id);
          });
        }
      });

      container.innerHTML = '';
      container.appendChild(grid);
    },

    // ============================================================================
    // STORIES
    // ============================================================================

    loadStories: function() {
      const container = document.getElementById('stories-container');
      if (!container) return;

      window.iNodesAPI.stories.getAll()
        .then(function(storiesData) {
          window.iNodesUI.renderStories(storiesData);
        })
        .catch(function(error) {
          console.error('Load stories error:', error);
        });
    },

    renderStories: function(storiesData) {
      const container = document.getElementById('stories-container');
      if (!container) return;

      if (!storiesData || storiesData.length === 0) {
        container.innerHTML = '<div class="empty-state">No stories</div>';
        return;
      }

      container.innerHTML = '';
      
      storiesData.forEach(function(data) {
        const storyEl = window.iNodesUI.createStoryElement(data);
        container.appendChild(storyEl);
      });
    },

    createStoryElement: function(data) {
      const div = document.createElement('div');
      div.className = 'story-item' + (data.hasUnseen ? ' unseen' : '');

      const author = data.author;
      const avatarUrl = (author.avatar && author.avatar.url) ? author.avatar.url : window.iNodesUtils.getDefaultAvatar();
      
      div.innerHTML = 
        '<img src="' + avatarUrl + '" alt="Avatar" class="story-avatar">' +
        '<span class="story-username">' + window.iNodesUtils.escapeHtml(author.displayName || author.username) + '</span>';

      div.addEventListener('click', function() {
        window.iNodesUI.showStoryViewer(data.stories);
      });

      return div;
    },

    updateStoriesBar: function() {
      window.iNodesUI.loadStories();
    },

    // ============================================================================
    // MODALS (Placeholders - would implement full modal system)
    // ============================================================================

    showCreatePostModal: function() {
      window.iNodesUtils.showToast('Create post modal - to be implemented', 'info');
    },

    showCreateStoryModal: function() {
      window.iNodesUtils.showToast('Create story modal - to be implemented', 'info');
    },

    showNewChatModal: function() {
      window.iNodesUtils.showToast('New chat modal - to be implemented', 'info');
    },

    showPostModal: function(postId) {
      window.iNodesUtils.showToast('Post detail modal - to be implemented', 'info');
    },

    showStoryViewer: function(stories) {
      window.iNodesUtils.showToast('Story viewer - to be implemented', 'info');
    },

    // ============================================================================
    // UTILITY UI FUNCTIONS
    // ============================================================================

    updateMessageStatus: function(messageId, status) {
      const messageEl = document.querySelector('.message[data-message-id="' + messageId + '"]');
      if (messageEl) {
        const timeEl = messageEl.querySelector('.message-time');
        if (timeEl && status === 'read') {
          timeEl.textContent = timeEl.textContent + ' ✓✓';
        }
      }
    },

    updateMessageReactions: function(messageId, reactions) {
      const messageEl = document.querySelector('.message[data-message-id="' + messageId + '"]');
      if (!messageEl) return;

      let reactionsEl = messageEl.querySelector('.message-reactions');
      
      if (reactions && reactions.length > 0) {
        const reactionsHtml = reactions.map(function(r) { return r.reaction; }).join(' ');
        
        if (reactionsEl) {
          reactionsEl.innerHTML = reactionsHtml;
        } else {
          const bubble = messageEl.querySelector('.message-bubble');
          reactionsEl = document.createElement('div');
          reactionsEl.className = 'message-reactions';
          reactionsEl.innerHTML = reactionsHtml;
          bubble.appendChild(reactionsEl);
        }
      } else {
        if (reactionsEl) {
          reactionsEl.remove();
        }
      }
    },

    updateMessageContent: function(messageId, content) {
      const messageEl = document.querySelector('.message[data-message-id="' + messageId + '"]');
      if (!messageEl) return;

      const bubble = messageEl.querySelector('.message-bubble div');
      if (bubble) {
        bubble.textContent = content + ' (edited)';
      }
    },

    removeMessage: function(messageId) {
      const messageEl = document.querySelector('.message[data-message-id="' + messageId + '"]');
      if (messageEl) {
        messageEl.remove();
      }
    },

    removeChatFromList: function(chatId) {
      const chatEl = document.querySelector('.chat-item[data-chat-id="' + chatId + '"]');
      if (chatEl) {
        chatEl.remove();
      }
    },

    closeActiveChat: function() {
      document.getElementById('active-chat').style.display = 'none';
      document.getElementById('no-chat-selected').style.display = 'flex';
      window.iNodesApp.currentChat = null;
    },

    updateUserPresence: function(userId, isOnline, lastSeen) {
      // Update presence in chat header if viewing that user's chat
      const chatStatus = document.getElementById('chat-status');
      if (chatStatus && window.iNodesApp.currentChat) {
        // Would need to check if current chat is with this user
        if (isOnline) {
          chatStatus.textContent = 'Online';
          chatStatus.style.color = '#4cd964';
        } else {
          chatStatus.textContent = 'Offline';
          chatStatus.style.color = '#8e8e8e';
        }
      }
    }
  };

  // ============================================================================
  // SEARCH FUNCTIONALITY
  // ============================================================================

  window.iNodesSearch = {
    init: function() {
      const searchInput = document.getElementById('explore-search');
      if (!searchInput) return;

      const debouncedSearch = window.iNodesUtils.debounce(function(query) {
        if (query.trim().length < 2) return;
        window.iNodesSearch.performSearch(query);
      }, 500);

      searchInput.addEventListener('input', function() {
        debouncedSearch(this.value);
      });
    },

    performSearch: function(query) {
      const container = document.getElementById('explore-container');
      if (!container) return;

      container.innerHTML = '<div class="loading">Searching...</div>';

      window.iNodesAPI.search({ q: query, type: 'users' })
        .then(function(data) {
          window.iNodesSearch.renderSearchResults(data);
        })
        .catch(function(error) {
          console.error('Search error:', error);
          container.innerHTML = '<div class="error">Search failed</div>';
        });
    },

    renderSearchResults: function(data) {
      const container = document.getElementById('explore-container');
      if (!container) return;

      if (!data.results || data.results.length === 0) {
        container.innerHTML = '<div class="empty-state">No results found</div>';
        return;
      }

      container.innerHTML = '<div class="search-section"><h3>Users</h3><div class="users-list"></div></div>';
      const usersList = container.querySelector('.users-list');

      data.results.forEach(function(user) {
        const userEl = document.createElement('div');
        userEl.className = 'user-item';
        
        const avatarUrl = (user.avatar && user.avatar.url) ? user.avatar.url : window.iNodesUtils.getDefaultAvatar();
        
        userEl.innerHTML = 
          '<img src="' + avatarUrl + '" alt="Avatar" class="avatar">' +
          '<div>' +
            '<strong>' + window.iNodesUtils.escapeHtml(user.displayName || user.username) + '</strong>' +
            (user.isVerified ? '<span class="verified">✓</span>' : '') +
            '<p class="text-muted">@' + window.iNodesUtils.escapeHtml(user.username) + '</p>' +
          '</div>';

        userEl.addEventListener('click', function() {
          window.iNodesUtils.showToast('View user profile - to be implemented', 'info');
        });

        usersList.appendChild(userEl);
      });
    }
  };

  // ============================================================================
  // MEDIA UPLOAD HANDLER
  // ============================================================================

  window.iNodesMedia = {
    validateFile: function(file) {
      const maxSize = 100 * 1024 * 1024; // 100MB
      const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'video/mp4', 'video/mov', 'video/avi'];

      if (file.size > maxSize) {
        window.iNodesUtils.showToast('File too large. Max 100MB', 'error');
        return false;
      }

      if (!allowedTypes.includes(file.type)) {
        window.iNodesUtils.showToast('Invalid file type', 'error');
        return false;
      }

      return true;
    },

    createPreview: function(file, callback) {
      const reader = new FileReader();
      
      reader.onload = function(e) {
        if (file.type.startsWith('image/')) {
          const img = document.createElement('img');
          img.src = e.target.result;
          img.className = 'media-preview-item';
          callback(img);
        } else if (file.type.startsWith('video/')) {
          const video = document.createElement('video');
          video.src = e.target.result;
          video.className = 'media-preview-item';
          video.controls = true;
          callback(video);
        }
      };

      reader.readAsDataURL(file);
    },

    uploadToCloudinary: function(file, progressCallback) {
      // This would handle direct Cloudinary upload
      // For now, we'll use the server endpoint
      return Promise.resolve(file);
    }
  };

  // ============================================================================
  // MODAL SYSTEM
  // ============================================================================

  window.iNodesModal = {
    create: function(title, content, options) {
      options = options || {};

      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay';
      overlay.id = 'modal-' + Date.now();

      const modal = document.createElement('div');
      modal.className = 'modal';

      modal.innerHTML = 
        '<div class="modal-header">' +
          '<h3>' + window.iNodesUtils.escapeHtml(title) + '</h3>' +
          '<button class="modal-close">✕</button>' +
        '</div>' +
        '<div class="modal-body">' +
          content +
        '</div>';

      overlay.appendChild(modal);
      document.body.appendChild(overlay);

      // Close button
      const closeBtn = modal.querySelector('.modal-close');
      closeBtn.addEventListener('click', function() {
        window.iNodesModal.close(overlay.id);
      });

      // Click outside to close
      if (options.closeOnOutsideClick !== false) {
        overlay.addEventListener('click', function(e) {
          if (e.target === overlay) {
            window.iNodesModal.close(overlay.id);
          }
        });
      }

      // Show with animation
      setTimeout(function() {
        overlay.classList.add('show');
      }, 10);

      return overlay.id;
    },

    close: function(modalId) {
      const overlay = document.getElementById(modalId);
      if (!overlay) return;

      overlay.classList.remove('show');
      setTimeout(function() {
        overlay.remove();
      }, 300);
    },

    createPostModal: function() {
      const content = 
        '<form id="create-post-form">' +
          '<div class="form-group">' +
            '<textarea id="post-caption" placeholder="What\'s on your mind?" rows="4"></textarea>' +
          '</div>' +
          '<div class="form-group">' +
            '<input type="file" id="post-media" accept="image/*,video/*" multiple>' +
            '<div id="post-media-preview" class="media-preview"></div>' +
          '</div>' +
          '<div class="form-group">' +
            '<label>Visibility</label>' +
            '<select id="post-visibility">' +
              '<option value="public">Public</option>' +
              '<option value="followers">Followers Only</option>' +
              '<option value="private">Private</option>' +
            '</select>' +
          '</div>' +
          '<button type="submit" class="btn btn-primary btn-block">Create Post</button>' +
        '</form>';

      const modalId = window.iNodesModal.create('Create Post', content);

      // Handle form submission
      setTimeout(function() {
        const form = document.getElementById('create-post-form');
        const mediaInput = document.getElementById('post-media');
        const preview = document.getElementById('post-media-preview');

        if (mediaInput) {
          mediaInput.addEventListener('change', function() {
            preview.innerHTML = '';
            Array.from(this.files).forEach(function(file) {
              if (window.iNodesMedia.validateFile(file)) {
                window.iNodesMedia.createPreview(file, function(previewEl) {
                  preview.appendChild(previewEl);
                });
              }
            });
          });
        }

        if (form) {
          form.addEventListener('submit', function(e) {
            e.preventDefault();

            const caption = document.getElementById('post-caption').value;
            const visibility = document.getElementById('post-visibility').value;
            const files = mediaInput.files;

            const formData = new FormData();
            formData.append('caption', caption);
            formData.append('visibility', visibility);

            Array.from(files).forEach(function(file) {
              formData.append('media', file);
            });

            window.iNodesAPI.posts.create(formData)
              .then(function(post) {
                window.iNodesUtils.showToast('Post created!', 'success');
                window.iNodesModal.close(modalId);
                
                // Prepend to feed if on feed view
                if (window.iNodesApp.currentView === 'feed') {
                  window.iNodesUI.prependPostToFeed(post);
                }
              })
              .catch(function(error) {
                console.error('Create post error:', error);
                window.iNodesUtils.showToast('Failed to create post', 'error');
              });
          });
        }
      }, 100);
    },

    createStoryModal: function() {
      const content = 
        '<form id="create-story-form">' +
          '<div class="form-group">' +
            '<input type="file" id="story-media" accept="image/*,video/*" required>' +
            '<div id="story-media-preview" class="media-preview"></div>' +
          '</div>' +
          '<div class="form-group">' +
            '<label>Visibility</label>' +
            '<select id="story-visibility">' +
              '<option value="followers">Followers</option>' +
              '<option value="close_friends">Close Friends</option>' +
              '<option value="public">Public</option>' +
            '</select>' +
          '</div>' +
          '<button type="submit" class="btn btn-primary btn-block">Share Story</button>' +
        '</form>';

      const modalId = window.iNodesModal.create('Create Story', content);

      setTimeout(function() {
        const form = document.getElementById('create-story-form');
        const mediaInput = document.getElementById('story-media');
        const preview = document.getElementById('story-media-preview');

        if (mediaInput) {
          mediaInput.addEventListener('change', function() {
            preview.innerHTML = '';
            const file = this.files[0];
            if (file && window.iNodesMedia.validateFile(file)) {
              window.iNodesMedia.createPreview(file, function(previewEl) {
                preview.appendChild(previewEl);
              });
            }
          });
        }

        if (form) {
          form.addEventListener('submit', function(e) {
            e.preventDefault();

            const visibility = document.getElementById('story-visibility').value;
            const file = mediaInput.files[0];

            if (!file) {
              window.iNodesUtils.showToast('Please select a media file', 'error');
              return;
            }

            const formData = new FormData();
            formData.append('media', file);
            formData.append('visibility', visibility);

            window.iNodesAPI.stories.create(formData)
              .then(function(story) {
                window.iNodesUtils.showToast('Story created!', 'success');
                window.iNodesModal.close(modalId);
                window.iNodesUI.updateStoriesBar();
              })
              .catch(function(error) {
                console.error('Create story error:', error);
                window.iNodesUtils.showToast('Failed to create story', 'error');
              });
          });
        }
      }, 100);
    },

    createChatModal: function() {
      const content = 
        '<form id="new-chat-form">' +
          '<div class="form-group">' +
            '<input type="text" id="chat-search" placeholder="Search users..." autocomplete="off">' +
            '<div id="chat-user-results" class="users-list" style="max-height: 300px; overflow-y: auto;"></div>' +
          '</div>' +
        '</form>';

      const modalId = window.iNodesModal.create('New Chat', content);

      setTimeout(function() {
        const searchInput = document.getElementById('chat-search');
        const resultsContainer = document.getElementById('chat-user-results');

        if (searchInput) {
          const debouncedSearch = window.iNodesUtils.debounce(function(query) {
            if (query.trim().length < 2) {
              resultsContainer.innerHTML = '';
              return;
            }

            window.iNodesAPI.search({ q: query, type: 'users' })
              .then(function(data) {
                resultsContainer.innerHTML = '';
                
                if (!data.results || data.results.length === 0) {
                  resultsContainer.innerHTML = '<p class="text-muted">No users found</p>';
                  return;
                }

                data.results.forEach(function(user) {
                  const userEl = document.createElement('div');
                  userEl.className = 'user-item';
                  
                  const avatarUrl = (user.avatar && user.avatar.url) ? user.avatar.url : window.iNodesUtils.getDefaultAvatar();
                  
                  userEl.innerHTML = 
                    '<img src="' + avatarUrl + '" alt="Avatar" class="avatar">' +
                    '<div>' +
                      '<strong>' + window.iNodesUtils.escapeHtml(user.displayName || user.username) + '</strong>' +
                      '<p class="text-muted">@' + window.iNodesUtils.escapeHtml(user.username) + '</p>' +
                    '</div>';

                  userEl.addEventListener('click', function() {
                    window.iNodesAPI.chats.create({
                      participantIds: [user._id],
                      isGroup: false
                    })
                    .then(function(chat) {
                      window.iNodesUtils.showToast('Chat created', 'success');
                      window.iNodesModal.close(modalId);
                      window.iNodesUI.switchView('messages');
                      window.iNodesUI.openChat(chat._id);
                    })
                    .catch(function(error) {
                      console.error('Create chat error:', error);
                      window.iNodesUtils.showToast('Failed to create chat', 'error');
                    });
                  });

                  resultsContainer.appendChild(userEl);
                });
              })
              .catch(function(error) {
                console.error('Search error:', error);
              });
          }, 500);

          searchInput.addEventListener('input', function() {
            debouncedSearch(this.value);
          });
        }
      }, 100);
    }
  };

  // ============================================================================
  // OVERRIDE UI MODAL FUNCTIONS
  // ============================================================================

  window.iNodesUI.showCreatePostModal = function() {
    window.iNodesModal.createPostModal();
  };

  window.iNodesUI.showCreateStoryModal = function() {
    window.iNodesModal.createStoryModal();
  };

  window.iNodesUI.showNewChatModal = function() {
    window.iNodesModal.createChatModal();
  };

  // Initialize search when explore view loads
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      window.iNodesSearch.init();
    });
  } else {
    window.iNodesSearch.init();
  }

})();