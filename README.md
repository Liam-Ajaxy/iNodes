# iNodes - Social Media & Messaging Platform

A complete Instagram/WhatsApp competitor with real-time messaging, stories, posts, and advanced features.

## 🚀 Features

### Core Features
- ✅ **User Authentication** - JWT with rotating refresh tokens
- ✅ **Posts** - Multi-media posts with likes, comments, hashtags
- ✅ **Stories** - 24-hour ephemeral content with viewers tracking
- ✅ **Real-time Messaging** - Encrypted 1-on-1 and group chats
- ✅ **Notifications** - Real-time push notifications via Socket.IO
- ✅ **Search** - Users, posts, and hashtags
- ✅ **Follow System** - Public/private profiles
- ✅ **Media Management** - Cloudinary CDN integration

### Advanced Features
- 🔐 **End-to-End Message Encryption** (AES-256-CBC)
- 👥 **Group Chats** with roles (owner, admin, member)
- 💬 **Message Reactions & Replies**
- ✏️ **Edit Messages** (15-minute window)
- 👻 **Ephemeral & View-Once Messages**
- 🔴 **Real-time Presence** (online/offline status)
- ⌨️ **Typing Indicators**
- ✅ **Read Receipts & Delivery Status**
- 🚫 **Block Users**
- 📊 **Admin Dashboard** for moderation

## 📋 Prerequisites

- **Node.js** >= 18.0.0
- **npm** >= 9.0.0
- **MongoDB Atlas** account (free tier works)
- **Cloudinary** account (free tier works)

## 🛠️ Installation

### 1. Clone Repository

```bash
git clone <repository-url>
cd INODES
```

### 2. Backend Setup

```bash
cd backend
npm install
```

### 3. Environment Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and configure:

#### MongoDB Atlas Setup
1. Go to [MongoDB Atlas](https://cloud.mongodb.com)
2. Create a free cluster
3. Create a database user
4. Whitelist your IP (or `0.0.0.0/0` for development)
5. Get connection string and update `MONGO_URI`

#### Cloudinary Setup
1. Go to [Cloudinary](https://cloudinary.com)
2. Sign up for free account
3. Copy credentials from dashboard
4. Update `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET`
5. Create upload preset:
   - Go to Settings > Upload
   - Add Upload Preset
   - Name: `inodes_unsigned`
   - Signing Mode: `Unsigned`

#### Generate Secure Secrets

```bash
# Generate JWT secrets (run twice for access & refresh)
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Generate encryption key (exactly 32 characters)
node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
```

### 4. Start Backend Server

```bash
# Development with auto-reload
npm run dev

# Production
npm start
```

Server will start on `http://localhost:4000`

### 5. Frontend Setup

```bash
cd ../frontend
# No build step needed - vanilla JavaScript
```

Open `http://localhost:4000` in your browser

## 📁 Project Structure

```
INODES/
├── backend/
│   ├── server.js          # Main server file with all routes
│   ├── package.json       # Dependencies
│   ├── .env               # Environment variables (create this)
│   ├── .env.example       # Environment template
│   └── uploads/           # Temporary upload directory
│
└── frontend/
    ├── index.html         # Main HTML file
    ├── css/
    │   └── style.css      # Styles
    └── js/
        └── main.js        # All JavaScript logic
```

## 🔌 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout user

### Users
- `GET /api/users/me` - Get current user profile
- `PUT /api/users/me` - Update profile (supports avatar upload)
- `GET /api/users/:username` - Get user profile by username
- `POST /api/users/:id/follow` - Follow/unfollow user
- `POST /api/users/:id/block` - Block/unblock user

### Posts
- `POST /api/posts` - Create post (supports multiple media)
- `GET /api/posts?feedType=home|explore|user` - Get posts feed
- `POST /api/posts/:id/like` - Like/unlike post
- `POST /api/posts/:id/comment` - Add comment
- `DELETE /api/posts/:id` - Delete post

### Stories
- `POST /api/stories` - Create story
- `GET /api/stories` - Get stories from following
- `POST /api/stories/:id/view` - Mark story as viewed

### Chats & Messages
- `POST /api/chats` - Create chat (1-on-1 or group)
- `GET /api/chats` - Get all user chats
- `GET /api/chats/:chatId/messages` - Get messages (paginated)
- `POST /api/messages` - Send message
- `POST /api/messages/:id/read` - Mark message as read
- `POST /api/messages/:id/react` - React to message
- `PUT /api/messages/:id` - Edit message
- `DELETE /api/messages/:id` - Delete message

### Group Management
- `POST /api/chats/:id/add` - Add participants
- `POST /api/chats/:id/remove` - Remove participant

### Media
- `GET /api/media/sign` - Get Cloudinary upload signature
- `POST /api/media/confirm` - Confirm media upload

### Notifications
- `GET /api/notifications` - Get notifications
- `PUT /api/notifications/:id/read` - Mark as read

### Search
- `GET /api/search?q=query&type=users|posts|hashtags` - Search

### Admin
- `GET /admin/reports` - Get reported content
- `POST /admin/users/:id/ban` - Ban user

## 🔌 Socket.IO Events

### Client → Server
- `socket_auth` - Authenticate socket connection
- `join_chat` - Join chat room
- `leave_chat` - Leave chat room
- `typing` - Send typing indicator
- `presence_ping` - Update online status
- `message_delivered` - Confirm message delivery

### Server → Client
- `auth_success` / `auth_error` - Authentication result
- `receive_message` - New message received
- `message_status_update` - Message status changed
- `user_online` / `user_offline` - User presence changed
- `user_typing` - Someone is typing
- `notification` - New notification
- `post_created` - New post from following
- `story_added` - New story from following
- `message_reaction` - Message reaction added
- `message_edited` - Message was edited
- `message_deleted` - Message was deleted
- `chat_updated` - Chat info updated
- `removed_from_chat` - Removed from group

## 🔒 Security Features

1. **Password Security** - bcrypt hashing (cost factor 12)
2. **JWT Authentication** - Short-lived access tokens (15min), long-lived refresh tokens (30d)
3. **Token Rotation** - Refresh tokens are rotated on each use
4. **Message Encryption** - AES-256-CBC encryption for message content
5. **Rate Limiting** - Per-IP and per-user limits
6. **Input Validation** - All inputs sanitized and validated
7. **CORS** - Configured for security
8. **Helmet.js** - Security headers
9. **File Validation** - MIME type and size checks
10. **Idempotency** - Prevent duplicate message sends

## 🎯 Frontend API (INodes Namespace)

All frontend functions are accessible via the global `INodes` object:

```javascript
// Authentication
INodes.registerUser({ username, email, password })
INodes.loginUser({ usernameOrEmail, password })
INodes.logoutUser()
INodes.refreshAccessToken()

// User Profile
INodes.getUserProfile(username)
INodes.updateProfile(formData)

// Posts
INodes.createPost(formData)
INodes.fetchPosts({ page, feedType })
INodes.likePost(postId)
INodes.commentPost(postId, text)

// Stories
INodes.createStory(file, { visibility })
INodes.fetchStories()
INodes.viewStory(storyId)

// Messaging
INodes.createOrGetDirectChat(participantId)
INodes.fetchChats()
INodes.fetchMessages(chatId, { before, limit })
INodes.sendMessage(chatId, content, { media, ephemeral, viewOnce })
INodes.markMessageAsRead(chatId, messageId)
INodes.reactToMessage(messageId, reaction)

// Socket
INodes.connectSocket()
INodes.disconnectSocket()
INodes.onMessageReceived(callback)
INodes.onTyping(callback)

// Utilities
INodes.search(query, type)
INodes.checkConnection()
INodes.showToast(message, options)
```

## 📊 Database Models

### User
- Authentication (username, email, password)
- Profile (displayName, avatar, bio)
- Social (followers, following, blockedUsers)
- Settings (privacy, message preferences)
- Devices (multi-device support)

### Post
- Content (caption, media[], hashtags, mentions)
- Engagement (likes, comments, likesCount)
- Visibility (public, followers, private)
- Reports (for moderation)

### Story
- Media (url, publicId, type)
- Expiration (24-hour TTL)
- Viewers tracking
- Visibility controls

### Chat
- Type (1-on-1 or group)
- Participants with roles
- Last message reference

### Message
- Content (encrypted)
- Media attachment
- Status (sent, delivered, read)
- Reactions, replies
- Ephemeral & view-once flags

### Notification
- Types (message, like, comment, follow, etc.)
- Source references
- Read status

## 🚀 Deployment

### Environment Variables for Production

Update `.env` for production:
- Change all secrets to strong random values
- Set `NODE_ENV=production`
- Use production MongoDB cluster
- Configure production `FRONTEND_URL`

### Recommended Platforms

- **Backend**: Railway, Render, Heroku, AWS EC2
- **Database**: MongoDB Atlas (already cloud-based)
- **Media**: Cloudinary (already CDN-based)
- **Socket.IO**: Requires sticky sessions or Redis adapter for multi-server

### Production Considerations

1. **HTTPS Required** - For secure WebSocket connections
2. **Redis Adapter** - For Socket.IO scaling across multiple servers
3. **Process Manager** - Use PM2 or similar
4. **Environment Variables** - Never commit secrets
5. **Database Indexes** - Already defined in models
6. **Monitoring** - Consider Sentry for error tracking
7. **Backups** - MongoDB Atlas provides automatic backups

## 🧪 Testing

```bash
npm test              # Run all tests
npm run test:watch    # Watch mode
npm run test:coverage # Coverage report
```

## 📝 Development Workflow

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature
   ```

2. **Make Changes**
   - Backend: Edit `server.js`
   - Frontend: Edit `main.js`, `style.css`, `index.html`

3. **Test Locally**
   ```bash
   npm run dev
   ```

4. **Commit & Push**
   ```bash
   git add .
   git commit -m "Description of changes"
   git push origin feature/your-feature
   ```

## 🐛 Troubleshooting

### MongoDB Connection Failed
- Check `MONGO_URI` in `.env`
- Verify IP whitelist in MongoDB Atlas
- Ensure database user credentials are correct

### Cloudinary Upload Failed
- Verify credentials in `.env`
- Check upload preset exists (`inodes_unsigned`)
- Ensure preset is set to "Unsigned" mode

### Socket.IO Not Connecting
- Check CORS configuration
- Verify frontend URL matches `FRONTEND_URL` in `.env`
- Check browser console for errors

### Messages Not Encrypting
- Ensure `ENCRYPTION_KEY` is exactly 32 characters
- Regenerate key if needed

## 📚 Additional Resources

- [Express Documentation](https://expressjs.com/)
- [MongoDB Documentation](https://docs.mongodb.com/)
- [Socket.IO Documentation](https://socket.io/docs/)
- [Cloudinary Documentation](https://cloudinary.com/documentation)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please read contributing guidelines first.

## ⚠️ Security

Found a security vulnerability? Please email security@example.com instead of opening an issue.

---

Built using Node.js, Express, MongoDB, Socket.IO, and Cloudinary