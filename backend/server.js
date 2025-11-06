// iNodes Backend Server - Complete Implementation
// Stack: Express, MongoDB, Socket.IO, Cloudinary, JWT Auth

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const crypto = require('crypto');
const http = require('http');
const socketIO = require('socket.io');
const cloudinary = require('cloudinary').v2;
const path = require('path');

// ============================================================================
// CONFIGURATION
// ============================================================================

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
  }
});

const PORT = process.env.PORT || 4000;

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// ============================================================================
// MIDDLEWARE
// ============================================================================

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'", "ws:", "wss:", "http://localhost:4000"],
      imgSrc: ["'self'", "data:", "https://res.cloudinary.com", "https://via.placeholder.com"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  }
}));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 120,
  message: { success: false, error: 'Too many requests' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, error: 'Too many auth attempts' }
});

app.use('/api/', apiLimiter);

// Serve frontend
app.use(express.static(path.join(__dirname, '../frontend')));

// ============================================================================
// DATABASE MODELS
// ============================================================================

// User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    minlength: 3,
    maxlength: 30,
    match: /^[a-zA-Z0-9._-]+$/
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  },
  password: { type: String, required: true },
  displayName: { type: String, default: '' },
  avatar: {
    url: { type: String, default: '' },
    publicId: { type: String, default: '' }
  },
  bio: { type: String, default: '', maxlength: 500 },
  createdAt: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now },
  devices: [{
    deviceId: String,
    lastActiveAt: Date,
    pushToken: String
  }],
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  isPrivate: { type: Boolean, default: false },
  isVerified: { type: Boolean, default: false },
  role: {
    type: String,
    enum: ['user', 'creator', 'business', 'admin'],
    default: 'user'
  },
  blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  settings: {
    storyPrivacy: {
      type: String,
      enum: ['all', 'followers', 'close_friends'],
      default: 'followers'
    },
    allowMessagesFrom: {
      type: String,
      enum: ['everyone', 'followers', 'none'],
      default: 'followers'
    },
    showLastSeen: { type: Boolean, default: true },
    allowProfileDiscovery: { type: Boolean, default: true }
  }
});

userSchema.index({ username: 1 });
userSchema.index({ email: 1 });

// Session Token Schema (for refresh tokens)
const sessionTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  refreshTokenHash: { type: String, required: true },
  deviceId: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
});

sessionTokenSchema.index({ userId: 1, deviceId: 1 });
sessionTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Post Schema
const postSchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  caption: { type: String, default: '', maxlength: 2200 },
  media: [{
    url: String,
    publicId: String,
    type: { type: String, enum: ['image', 'video'] },
    width: Number,
    height: Number,
    duration: Number
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  likesCount: { type: Number, default: 0 },
  comments: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    createdAt: { type: Date, default: Date.now }
  }],
  visibility: {
    type: String,
    enum: ['public', 'followers', 'private'],
    default: 'public'
  },
  hashtags: [String],
  mentions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  reports: [{
    reporterId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reason: String,
    createdAt: { type: Date, default: Date.now }
  }]
});

postSchema.index({ author: 1, createdAt: -1 });
postSchema.index({ hashtags: 1 });
postSchema.index({ createdAt: -1 });

// Story Schema
const storySchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  media: {
    url: String,
    publicId: String,
    type: { type: String, enum: ['image', 'video'] }
  },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
  viewers: {
    type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    default: []
  },
  visibility: {
    type: String,
    enum: ['public', 'followers', 'close_friends'],
    default: 'followers'
  },
  archived: { type: Boolean, default: false }
});

storySchema.index({ expiresAt: 1 });
storySchema.index({ author: 1, createdAt: -1 });



// Chat Schema
const chatSchema = new mongoose.Schema({
  isGroup: { type: Boolean, default: false },
  name: { type: String, default: '' },
  participants: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    role: {
      type: String,
      enum: ['member', 'admin', 'owner'],
      default: 'member'
    },
    joinedAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  isPublicChannel: { type: Boolean, default: false },
  metadata: {
    topic: String,
    description: String,
    coverImage: String
  }
});

chatSchema.index({ 'participants.userId': 1 });
chatSchema.index({ updatedAt: -1 });

// Message Schema
const messageSchema = new mongoose.Schema({
  chat: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true }, // Encrypted payload
  media: {
    url: String,
    publicId: String,
    type: String
  },
  createdAt: { type: Date, default: Date.now },
  status: {
    type: String,
    enum: ['sent', 'delivered', 'read'],
    default: 'sent'
  },
  readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  replyTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  reactions: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reaction: String
  }],
  ephemeral: { type: Boolean, default: false },
  viewOnce: { type: Boolean, default: false },
  idempotencyKey: { type: String, unique: true, sparse: true }
});

messageSchema.index({ chat: 1, createdAt: 1 });
messageSchema.index({ idempotencyKey: 1 }, { sparse: true });

// Notification Schema
const notificationSchema = new mongoose.Schema({
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  actor: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: {
    type: String,
    enum: ['message', 'like', 'comment', 'follow', 'story_view', 'mention', 'system'],
    required: true
  },
  source: {
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
    chatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat' },
    messageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
    storyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Story' }
  },
  payload: { type: mongoose.Schema.Types.Mixed },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

notificationSchema.index({ recipient: 1, read: 1, createdAt: -1 });

// Models
const User = mongoose.model('User', userSchema);
const SessionToken = mongoose.model('SessionToken', sessionTokenSchema);
const Post = mongoose.model('Post', postSchema);
const Story = mongoose.model('Story', storySchema);
const Chat = mongoose.model('Chat', chatSchema);
const Message = mongoose.model('Message', messageSchema);
const Notification = mongoose.model('Notification', notificationSchema);

// ============================================================================
// ENCRYPTION UTILITIES
// ============================================================================

const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY || '12345678901234567890123456789012', 'utf8');
const ALGORITHM = 'aes-256-cbc';

function encrypt(text, chatId) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedData) {
  const parts = encryptedData.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];
  const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ============================================================================
// AUTH MIDDLEWARE
// ============================================================================

async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      status: 401,
      error: 'Access token required'
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        status: 401,
        error: 'User not found'
      });
    }

    req.user = user;
    req.userId = user._id;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      status: 401,
      error: 'Invalid or expired token'
    });
  }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function generateAccessToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '15m' });
}

function generateRefreshToken(userId, deviceId) {
  return jwt.sign({ userId, deviceId }, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' });
}

function sanitizeUser(user) {
  const userObj = user.toObject ? user.toObject() : user;
  delete userObj.password;
  return {
    ...userObj,
    followersCount: userObj.followers?.length || 0,
    followingCount: userObj.following?.length || 0
  };
}

function extractHashtags(text) {
  const regex = /#(\w+)/g;
  const hashtags = [];
  let match;
  while ((match = regex.exec(text)) !== null) {
    hashtags.push(match[1].toLowerCase());
  }
  return [...new Set(hashtags)];
}

function extractMentions(text) {
  const regex = /@(\w+)/g;
  const mentions = [];
  let match;
  while ((match = regex.exec(text)) !== null) {
    mentions.push(match[1].toLowerCase());
  }
  return [...new Set(mentions)];
}

// ============================================================================
// AUTH ROUTES
// ============================================================================

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        status: 400,
        error: 'Username, email, and password are required'
      });
    }

    if (password.length < 8 || !/\d/.test(password) || !/[a-zA-Z]/.test(password)) {
      return res.status(400).json({
        success: false,
        status: 400,
        error: 'Password must be at least 8 characters with at least 1 number and 1 letter'
      });
    }

    // Check existing user
    const existingUser = await User.findOne({
      $or: [{ username: username.toLowerCase() }, { email: email.toLowerCase() }]
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        status: 409,
        error: 'Username or email already exists'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = new User({
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      password: hashedPassword,
      displayName: displayName || username
    });

    await user.save();

    // Generate tokens
    const deviceId = req.body.deviceId || crypto.randomBytes(16).toString('hex');
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id, deviceId);

    // Store refresh token
    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    const sessionToken = new SessionToken({
      userId: user._id,
      refreshTokenHash,
      deviceId,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    });
    await sessionToken.save();

    res.status(201).json({
      success: true,
      status: 201,
      data: {
        user: sanitizeUser(user),
        accessToken,
        refreshToken
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Registration failed'
    });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { usernameOrEmail, password, deviceId } = req.body;

    if (!usernameOrEmail || !password) {
      return res.status(400).json({
        success: false,
        status: 400,
        error: 'Username/email and password are required'
      });
    }

    // Find user
    const user = await User.findOne({
      $or: [
        { username: usernameOrEmail.toLowerCase() },
        { email: usernameOrEmail.toLowerCase() }
      ]
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        status: 401,
        error: 'Invalid credentials'
      });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        status: 401,
        error: 'Invalid credentials'
      });
    }

    // Generate tokens
    const device = deviceId || crypto.randomBytes(16).toString('hex');
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id, device);

    // Store/update refresh token
    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    await SessionToken.findOneAndUpdate(
      { userId: user._id, deviceId: device },
      {
        refreshTokenHash,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date()
      },
      { upsert: true }
    );

    // Update device info
    const deviceIndex = user.devices.findIndex(d => d.deviceId === device);
    if (deviceIndex >= 0) {
      user.devices[deviceIndex].lastActiveAt = new Date();
    } else {
      user.devices.push({ deviceId: device, lastActiveAt: new Date() });
    }
    user.lastSeen = new Date();
    await user.save();

    res.json({
      success: true,
      status: 200,
      data: {
        user: sanitizeUser(user),
        accessToken,
        refreshToken
      }
    });

  } catch (error) {
    console.error('View story error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to view story'
    });
  }
});

// ============================================================================
// CHAT ROUTES
// ============================================================================

app.post('/api/chats', authenticateToken, async (req, res) => {
  try {
    const { participantIds, isGroup = false, name } = req.body;
    const currentUserId = req.userId;

    if (!participantIds || !Array.isArray(participantIds) || participantIds.length === 0) {
      return res.status(400).json({
        success: false,
        status: 400,
        error: 'Participant IDs are required'
      });
    }

    // For 1-on-1 chats, check if chat already exists
    if (!isGroup && participantIds.length === 1) {
      const existingChat = await Chat.findOne({
        isGroup: false,
        'participants.userId': { 
          $all: [currentUserId, participantIds[0]] 
        }
      }).populate('participants.userId', 'username displayName avatar')
        .populate('lastMessage');

      if (existingChat) {
        return res.json({
          success: true,
          status: 200,
          data: existingChat
        });
      }
    }

    // Create new chat
    const participants = [
      { userId: currentUserId, role: isGroup ? 'owner' : 'member' },
      ...participantIds.map(id => ({ userId: id, role: 'member' }))
    ];

    const chat = new Chat({
      isGroup,
      name: isGroup ? name : '',
      participants
    });

    await chat.save();
    await chat.populate('participants.userId', 'username displayName avatar');

    // Notify participants
    for (const participant of participantIds) {
      io.to(`user:${participant}`).emit('chat_created', { chat });
    }

    res.status(201).json({
      success: true,
      status: 201,
      data: chat
    });
  } catch (error) {
    console.error('Create chat error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to create chat'
    });
  }
});

app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;

    const chats = await Chat.find({
      'participants.userId': userId
    })
    .populate('participants.userId', 'username displayName avatar lastSeen')
    .populate({
      path: 'lastMessage',
      populate: { path: 'sender', select: 'username displayName avatar' }
    })
    .sort({ updatedAt: -1 });

    // Decrypt last message content for display
    const chatsWithDecrypted = chats.map(chat => {
      const chatObj = chat.toObject();
      if (chatObj.lastMessage && chatObj.lastMessage.content) {
        try {
          chatObj.lastMessage.decryptedContent = decrypt(chatObj.lastMessage.content);
        } catch (err) {
          chatObj.lastMessage.decryptedContent = '[Unable to decrypt]';
        }
      }

      // Calculate unread count
      chatObj.unreadCount = 0; // Would need separate tracking for efficiency
      
      return chatObj;
    });

    res.json({
      success: true,
      status: 200,
      data: chatsWithDecrypted
    });
  } catch (error) {
    console.error('Fetch chats error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to fetch chats'
    });
  }
});

app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { limit = 50, before } = req.query;
    const userId = req.userId;

    // Verify user is participant
    const chat = await Chat.findById(chatId);
    if (!chat) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'Chat not found'
      });
    }

    const isParticipant = chat.participants.some(p => p.userId.equals(userId));
    if (!isParticipant) {
      return res.status(403).json({
        success: false,
        status: 403,
        error: 'Not a participant of this chat'
      });
    }

    // Build query
    let query = { chat: chatId };
    if (before) {
      const beforeDate = new Date(before);
      query.createdAt = { $lt: beforeDate };
    }

    const messages = await Message.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .populate('sender', 'username displayName avatar')
      .populate('replyTo', 'content sender createdAt');

    // Decrypt messages
    const decryptedMessages = messages.reverse().map(msg => {
      const msgObj = msg.toObject();
      try {
        msgObj.decryptedContent = decrypt(msgObj.content);
        delete msgObj.content; // Remove encrypted content from response
      } catch (err) {
        msgObj.decryptedContent = '[Unable to decrypt]';
      }
      return msgObj;
    });

    res.json({
      success: true,
      status: 200,
      data: decryptedMessages
    });
  } catch (error) {
    console.error('Fetch messages error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to fetch messages'
    });
  }
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|mp4|mov|avi/;
    const mimeType = allowedTypes.test(file.mimetype);
    if (mimeType) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only images and videos allowed.'));
    }
  }
});

app.post('/api/messages', authenticateToken, upload.single('media'), async (req, res) => {
  try {
    const { chatId, content, idempotencyKey, ephemeral, viewOnce, replyTo } = req.body;
    const userId = req.userId;

    if (!chatId || !content) {
      return res.status(400).json({
        success: false,
        status: 400,
        error: 'Chat ID and content are required'
      });
    }

    // Verify chat and participation
    const chat = await Chat.findById(chatId);
    if (!chat) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'Chat not found'
      });
    }

    const isParticipant = chat.participants.some(p => p.userId.equals(userId));
    if (!isParticipant) {
      return res.status(403).json({
        success: false,
        status: 403,
        error: 'Not a participant of this chat'
      });
    }

    // Check idempotency
    if (idempotencyKey) {
      const existing = await Message.findOne({ idempotencyKey });
      if (existing) {
        const existingObj = existing.toObject();
        try {
          existingObj.decryptedContent = decrypt(existingObj.content);
          delete existingObj.content;
        } catch (err) {}
        return res.json({
          success: true,
          status: 200,
          data: existingObj
        });
      }
    }

    // Handle media upload
    let mediaData = null;
    if (req.file) {
      const isVideo = req.file.mimetype.startsWith('video/');
      const uploadResult = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: isVideo ? 'inodes/messages/videos' : 'inodes/messages/images',
            resource_type: isVideo ? 'video' : 'image'
          },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        uploadStream.end(req.file.buffer);
      });

      mediaData = {
        url: uploadResult.secure_url,
        publicId: uploadResult.public_id,
        type: isVideo ? 'video' : 'image'
      };
    }

    // Encrypt content
    const encryptedContent = encrypt(content, chatId);

    // Create message
    const message = new Message({
      chat: chatId,
      sender: userId,
      content: encryptedContent,
      media: mediaData,
      ephemeral: ephemeral === 'true' || ephemeral === true,
      viewOnce: viewOnce === 'true' || viewOnce === true,
      replyTo: replyTo || null,
      idempotencyKey: idempotencyKey || undefined
    });

    await message.save();
    await message.populate('sender', 'username displayName avatar');

    // Update chat
    chat.lastMessage = message._id;
    chat.updatedAt = new Date();
    await chat.save();

    // Prepare response with decrypted content
    const messageObj = message.toObject();
    messageObj.decryptedContent = content;
    delete messageObj.content;

    // Emit to participants via Socket.IO
    const participantIds = chat.participants.map(p => p.userId.toString());
    for (const participantId of participantIds) {
      io.to(`user:${participantId}`).emit('receive_message', messageObj);
    }

    // Create notifications for offline users
    for (const participant of chat.participants) {
      if (!participant.userId.equals(userId)) {
        const notification = new Notification({
          recipient: participant.userId,
          actor: userId,
          type: 'message',
          source: { chatId, messageId: message._id },
          payload: { preview: content.substring(0, 50) }
        });
        await notification.save();
      }
    }

    res.status(201).json({
      success: true,
      status: 201,
      data: messageObj
    });
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to send message'
    });
  }
});

app.post('/api/messages/:id/read', authenticateToken, async (req, res) => {
  try {
    const messageId = req.params.id;
    const userId = req.userId;

    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'Message not found'
      });
    }

    // Add to readBy if not already there
    if (!message.readBy.some(id => id.equals(userId))) {
      message.readBy.push(userId);
      message.status = 'read';
      await message.save();

      // Emit status update
      io.to(`user:${message.sender}`).emit('message_status_update', {
        messageId: message._id,
        chatId: message.chat,
        status: 'read',
        userId
      });
    }

    res.json({
      success: true,
      status: 200,
      data: { read: true }
    });
  } catch (error) {
    console.error('Mark read error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to mark message as read'
    });
  }
});

app.post('/api/messages/:id/react', authenticateToken, async (req, res) => {
  try {
    const messageId = req.params.id;
    const { reaction } = req.body;
    const userId = req.userId;

    if (!reaction) {
      return res.status(400).json({
        success: false,
        status: 400,
        error: 'Reaction is required'
      });
    }

    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'Message not found'
      });
    }

    // Toggle reaction
    const existingIndex = message.reactions.findIndex(r => r.user.equals(userId));
    if (existingIndex >= 0) {
      if (message.reactions[existingIndex].reaction === reaction) {
        // Remove reaction
        message.reactions.splice(existingIndex, 1);
      } else {
        // Update reaction
        message.reactions[existingIndex].reaction = reaction;
      }
    } else {
      // Add reaction
      message.reactions.push({ user: userId, reaction });
    }

    await message.save();

    // Emit to chat participants
    const chat = await Chat.findById(message.chat);
    for (const participant of chat.participants) {
      io.to(`user:${participant.userId}`).emit('message_reaction', {
        messageId: message._id,
        userId,
        reaction,
        reactions: message.reactions
      });
    }

    res.json({
      success: true,
      status: 200,
      data: { reactions: message.reactions }
    });
  } catch (error) {
    console.error('React error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to react to message'
    });
  }
});

app.put('/api/messages/:id', authenticateToken, async (req, res) => {
  try {
    const messageId = req.params.id;
    const { content } = req.body;
    const userId = req.userId;

    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'Message not found'
      });
    }

    if (!message.sender.equals(userId)) {
      return res.status(403).json({
        success: false,
        status: 403,
        error: 'Not authorized to edit this message'
      });
    }

    // Check edit window (15 minutes)
    const editWindow = 15 * 60 * 1000;
    if (Date.now() - message.createdAt.getTime() > editWindow) {
      return res.status(400).json({
        success: false,
        status: 400,
        error: 'Edit window expired'
      });
    }

    // Encrypt new content
    message.content = encrypt(content, message.chat);
    await message.save();

    // Emit update
    const chat = await Chat.findById(message.chat);
    for (const participant of chat.participants) {
      io.to(`user:${participant.userId}`).emit('message_edited', {
        messageId: message._id,
        chatId: message.chat,
        decryptedContent: content
      });
    }

    res.json({
      success: true,
      status: 200,
      data: { decryptedContent: content }
    });
  } catch (error) {
    console.error('Edit message error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to edit message'
    });
  }
});

app.delete('/api/messages/:id', authenticateToken, async (req, res) => {
  try {
    const messageId = req.params.id;
    const userId = req.userId;

    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'Message not found'
      });
    }

    // Check authorization
    const user = await User.findById(userId);
    if (!message.sender.equals(userId) && user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        status: 403,
        error: 'Not authorized to delete this message'
      });
    }

    // Delete media if exists
    if (message.media && message.media.publicId) {
      try {
        await cloudinary.uploader.destroy(message.media.publicId, {
          resource_type: message.media.type === 'video' ? 'video' : 'image'
        });
      } catch (err) {
        console.error('Error deleting media:', err);
      }
    }

    await Message.findByIdAndDelete(messageId);

    // Emit deletion
    const chat = await Chat.findById(message.chat);
    for (const participant of chat.participants) {
      io.to(`user:${participant.userId}`).emit('message_deleted', {
        messageId: message._id,
        chatId: message.chat
      });
    }

    res.json({
      success: true,
      status: 200,
      data: { deleted: true }
    });
  } catch (error) {
    console.error('Delete message error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to delete message'
    });
  }
});

// Group management endpoints
app.post('/api/chats/:id/add', authenticateToken, async (req, res) => {
  try {
    const chatId = req.params.id;
    const { userIds } = req.body;
    const userId = req.userId;

    const chat = await Chat.findById(chatId);
    if (!chat || !chat.isGroup) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'Group chat not found'
      });
    }

    // Check if requester is admin or owner
    const requesterParticipant = chat.participants.find(p => p.userId.equals(userId));
    if (!requesterParticipant || !['admin', 'owner'].includes(requesterParticipant.role)) {
      return res.status(403).json({
        success: false,
        status: 403,
        error: 'Only admins can add participants'
      });
    }

    // Add new participants
    for (const newUserId of userIds) {
      if (!chat.participants.some(p => p.userId.equals(newUserId))) {
        chat.participants.push({ userId: newUserId, role: 'member' });
      }
    }

    await chat.save();
    await chat.populate('participants.userId', 'username displayName avatar');

    // Notify all participants
    for (const participant of chat.participants) {
      io.to(`user:${participant.userId}`).emit('chat_updated', { chat });
    }

    res.json({
      success: true,
      status: 200,
      data: chat
    });
  } catch (error) {
    console.error('Add participant error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to add participants'
    });
  }
});

app.post('/api/chats/:id/remove', authenticateToken, async (req, res) => {
  try {
    const chatId = req.params.id;
    const { userId: targetUserId } = req.body;
    const userId = req.userId;

    const chat = await Chat.findById(chatId);
    if (!chat || !chat.isGroup) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'Group chat not found'
      });
    }

    // Check authorization
    const requesterParticipant = chat.participants.find(p => p.userId.equals(userId));
    const targetParticipant = chat.participants.find(p => p.userId.equals(targetUserId));

    if (!requesterParticipant || !targetParticipant) {
      return res.status(400).json({
        success: false,
        status: 400,
        error: 'Invalid participants'
      });
    }

    // Can remove self, or admin/owner can remove members
    const canRemove = userId === targetUserId || 
                      ['admin', 'owner'].includes(requesterParticipant.role);

    if (!canRemove) {
      return res.status(403).json({
        success: false,
        status: 403,
        error: 'Not authorized to remove this participant'
      });
    }

    // Remove participant
    chat.participants = chat.participants.filter(p => !p.userId.equals(targetUserId));
    await chat.save();

    // Notify
    io.to(`user:${targetUserId}`).emit('removed_from_chat', { chatId });
    for (const participant of chat.participants) {
      io.to(`user:${participant.userId}`).emit('chat_updated', { chat });
    }

    res.json({
      success: true,
      status: 200,
      data: { removed: true }
    });
  } catch (error) {
    console.error('Remove participant error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to remove participant'
    });
  }
});

// ============================================================================
// NOTIFICATION ROUTES
// ============================================================================

app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const userId = req.userId;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const notifications = await Notification.find({ recipient: userId })
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip)
      .populate('actor', 'username displayName avatar isVerified')
      .populate('source.postId', 'media caption')
      .populate('source.storyId', 'media');

    const total = await Notification.countDocuments({ recipient: userId });
    const unreadCount = await Notification.countDocuments({ recipient: userId, read: false });

    res.json({
      success: true,
      status: 200,
      data: {
        notifications,
        page: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        unreadCount
      }
    });
  } catch (error) {
    console.error('Fetch notifications error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to fetch notifications'
    });
  }
});

app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const notificationId = req.params.id;
    const userId = req.userId;

    const notification = await Notification.findOne({
      _id: notificationId,
      recipient: userId
    });

    if (!notification) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'Notification not found'
      });
    }

    notification.read = true;
    await notification.save();

    res.json({
      success: true,
      status: 200,
      data: notification
    });
  } catch (error) {
    console.error('Mark notification read error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to mark notification as read'
    });
  }
});

// ============================================================================
// SOCKET.IO IMPLEMENTATION
// ============================================================================

const connectedUsers = new Map(); // userId -> socket.id mapping

io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id);

  // Authentication
  socket.on('socket_auth', async (data) => {
    try {
      const { token } = data;
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.userId);

      if (!user) {
        socket.emit('auth_error', { error: 'User not found' });
        return;
      }

      socket.userId = decoded.userId;
      connectedUsers.set(decoded.userId.toString(), socket.id);

      // Join user's personal room
      socket.join(`user:${decoded.userId}`);

      // Update user online status
      user.lastSeen = new Date();
      await user.save();

      socket.emit('auth_success', { userId: decoded.userId });

      // Broadcast online status to followers
      for (const followerId of user.followers) {
        io.to(`user:${followerId}`).emit('user_online', { userId: decoded.userId });
      }

      console.log(`User ${decoded.userId} authenticated on socket ${socket.id}`);
    } catch (error) {
      console.error('Socket auth error:', error);
      socket.emit('auth_error', { error: 'Authentication failed' });
    }
  });

  // Join chat room
  socket.on('join_chat', async (data) => {
    try {
      const { chatId } = data;
      if (!socket.userId) {
        socket.emit('error', { error: 'Not authenticated' });
        return;
      }

      // Verify participation
      const chat = await Chat.findById(chatId);
      if (chat && chat.participants.some(p => p.userId.equals(socket.userId))) {
        socket.join(`chat:${chatId}`);
        console.log(`User ${socket.userId} joined chat ${chatId}`);
      }
    } catch (error) {
      console.error('Join chat error:', error);
    }
  });

  // Leave chat room
  socket.on('leave_chat', (data) => {
    const { chatId } = data;
    socket.leave(`chat:${chatId}`);
    console.log(`Socket ${socket.id} left chat ${chatId}`);
  });

  // Typing indicator
  socket.on('typing', async (data) => {
    try {
      const { chatId, isTyping } = data;
      if (!socket.userId) return;

      socket.to(`chat:${chatId}`).emit('user_typing', {
        chatId,
        userId: socket.userId,
        isTyping
      });
    } catch (error) {
      console.error('Typing error:', error);
    }
  });

  // Presence ping
  socket.on('presence_ping', async (data) => {
    try {
      if (socket.userId) {
        const user = await User.findById(socket.userId);
        if (user) {
          user.lastSeen = new Date();
          await user.save();
        }
      }
    } catch (error) {
      console.error('Presence ping error:', error);
    }
  });

  // Message delivery confirmation
  socket.on('message_delivered', async (data) => {
    try {
      const { chatId, messageId } = data;
      if (!socket.userId) return;

      const message = await Message.findById(messageId);
      if (message && message.status === 'sent') {
        message.status = 'delivered';
        await message.save();

        io.to(`user:${message.sender}`).emit('message_status_update', {
          messageId,
          chatId,
          status: 'delivered',
          userId: socket.userId
        });
      }
    } catch (error) {
      console.error('Message delivered error:', error);
    }
  });

  // Disconnect
  socket.on('disconnect', async () => {
    console.log('Socket disconnected:', socket.id);

    if (socket.userId) {
      connectedUsers.delete(socket.userId.toString());

      try {
        const user = await User.findById(socket.userId);
        if (user) {
          user.lastSeen = new Date();
          await user.save();

          // Broadcast offline status
          for (const followerId of user.followers) {
            io.to(`user:${followerId}`).emit('user_offline', {
              userId: socket.userId,
              lastSeen: user.lastSeen
            });
          }
        }
      } catch (error) {
        console.error('Disconnect update error:', error);
      }
    }
  });
});

// ============================================================================
// BACKGROUND WORKER - Story Cleanup
// ============================================================================

async function cleanupExpiredStories() {
  try {
    const expiredStories = await Story.find({
      expiresAt: { $lt: new Date() },
      archived: false
    });

    for (const story of expiredStories) {
      // Delete from Cloudinary
      if (story.media.publicId) {
        try {
          await cloudinary.uploader.destroy(story.media.publicId, {
            resource_type: story.media.type === 'video' ? 'video' : 'image'
          });
        } catch (err) {
          console.error('Error deleting story media:', err);
        }
      }

      // Delete story document
      await Story.findByIdAndDelete(story._id);
    }

    if (expiredStories.length > 0) {
      console.log(`Cleaned up ${expiredStories.length} expired stories`);
    }
  } catch (error) {
    console.error('Story cleanup error:', error);
  }
}

// Run cleanup every 5 minutes
setInterval(cleanupExpiredStories, 5 * 60 * 1000);

// ============================================================================
// ADMIN ROUTES
// ============================================================================

const adminAuth = async (req, res, next) => {
  await authenticateToken(req, res, async () => {
    const user = await User.findById(req.userId);
    if (user && user.role === 'admin') {
      next();
    } else {
      res.status(403).json({
        success: false,
        status: 403,
        error: 'Admin access required'
      });
    }
  });
};

app.get('/admin/reports', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const posts = await Post.find({ 'reports.0': { $exists: true } })
      .populate('author', 'username displayName')
      .populate('reports.reporterId', 'username')
      .limit(parseInt(limit))
      .skip(skip);

    res.json({
      success: true,
      status: 200,
      data: { reports: posts }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to fetch reports'
    });
  }
});

app.post('/admin/users/:id/ban', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    // Implement ban logic here
    res.json({
      success: true,
      status: 200,
      data: { message: 'User banned' }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to ban user'
    });
  }
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      success: false,
      status: 400,
      error: err.message
    });
  }

  res.status(500).json({
    success: false,
    status: 500,
    error: err.message || 'Internal server error'
  });
});

// ============================================================================
// DATABASE CONNECTION & SERVER START
// ============================================================================

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(async () => {   // 👈 make the callback async so you can use await
  console.log('✓ Connected to MongoDB Atlas');

  // Start server
  server.listen(PORT, () => {
    console.log(`✓ Server running on port ${PORT}`);
    console.log(`✓ Socket.IO ready for connections`);
    console.log(`✓ Cloudinary configured: ${process.env.CLOUDINARY_CLOUD_NAME}`);
    console.log('✓ Background workers started');
  });
})
.catch(err => {
  console.error('✗ MongoDB connection error:', err);
  process.exit(1);
});



app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken, deviceId } = req.body;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        status: 401,
        error: 'Refresh token required'
      });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // Find stored token
    const sessionToken = await SessionToken.findOne({
      userId: decoded.userId,
      deviceId: decoded.deviceId
    });

    if (!sessionToken) {
      return res.status(401).json({
        success: false,
        status: 401,
        error: 'Invalid refresh token'
      });
    }

    // Verify hash
    const validToken = await bcrypt.compare(refreshToken, sessionToken.refreshTokenHash);
    if (!validToken) {
      return res.status(401).json({
        success: false,
        status: 401,
        error: 'Invalid refresh token'
      });
    }

    // Generate new tokens
    const newAccessToken = generateAccessToken(decoded.userId);
    const newRefreshToken = generateRefreshToken(decoded.userId, decoded.deviceId);

    // Update stored token
    const newRefreshTokenHash = await bcrypt.hash(newRefreshToken, 10);
    sessionToken.refreshTokenHash = newRefreshTokenHash;
    sessionToken.expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await sessionToken.save();

    res.json({
      success: true,
      status: 200,
      data: {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken
      }
    });
  } catch (error) {
    console.error('Refresh error:', error);
    res.status(401).json({
      success: false,
      status: 401,
      error: 'Token refresh failed'
    });
  }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    const { refreshToken, deviceId } = req.body;

    if (refreshToken) {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, { ignoreExpiration: true });
      await SessionToken.deleteOne({
        userId: decoded.userId,
        deviceId: decoded.deviceId || deviceId
      });
    }

    res.json({
      success: true,
      status: 200,
      data: { message: 'Logged out successfully' }
    });
  } catch (error) {
    res.status(200).json({
      success: true,
      status: 200,
      data: { message: 'Logged out' }
    });
  }
});

// ============================================================================
// USER ROUTES
// ============================================================================

app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId)
      .populate('followers', 'username displayName avatar')
      .populate('following', 'username displayName avatar');

    res.json({
      success: true,
      status: 200,
      data: sanitizeUser(user)
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to fetch user'
    });
  }
});


app.put('/api/users/me', authenticateToken, upload.single('avatar'), async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const { displayName, bio, settings } = req.body;

    // Update basic fields
    if (displayName !== undefined) user.displayName = displayName;
    if (bio !== undefined) user.bio = bio;
    
    // Update settings
    if (settings) {
      const parsedSettings = typeof settings === 'string' ? JSON.parse(settings) : settings;
      if (parsedSettings.storyPrivacy) user.settings.storyPrivacy = parsedSettings.storyPrivacy;
      if (parsedSettings.allowMessagesFrom) user.settings.allowMessagesFrom = parsedSettings.allowMessagesFrom;
      if (parsedSettings.showLastSeen !== undefined) user.settings.showLastSeen = parsedSettings.showLastSeen;
      if (parsedSettings.allowProfileDiscovery !== undefined) user.settings.allowProfileDiscovery = parsedSettings.allowProfileDiscovery;
    }

    // Handle avatar upload
    if (req.file) {
      // Delete old avatar if exists
      if (user.avatar.publicId) {
        try {
          await cloudinary.uploader.destroy(user.avatar.publicId);
        } catch (err) {
          console.error('Error deleting old avatar:', err);
        }
      }

      // Upload new avatar
      const uploadResult = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: 'inodes/avatars',
            transformation: [
              { width: 400, height: 400, crop: 'fill', gravity: 'face' }
            ]
          },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        uploadStream.end(req.file.buffer);
      });

      user.avatar = {
        url: uploadResult.secure_url,
        publicId: uploadResult.public_id
      };
    }

    await user.save();

    res.json({
      success: true,
      status: 200,
      data: sanitizeUser(user)
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to update profile'
    });
  }
});

app.get('/api/users/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const requesterId = req.userId; // May be undefined if not authenticated

    const user = await User.findOne({ username: username.toLowerCase() })
      .select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'User not found'
      });
    }

    // Check if requester is blocked
    if (requesterId && user.blockedUsers.some(id => id.equals(requesterId))) {
      return res.status(403).json({
        success: false,
        status: 403,
        error: 'Access denied'
      });
    }

    // Get posts based on privacy settings
    let posts = [];
    if (!user.isPrivate || (requesterId && user.followers.some(id => id.equals(requesterId)))) {
      posts = await Post.find({ 
        author: user._id,
        visibility: { $in: ['public', 'followers'] }
      })
      .sort({ createdAt: -1 })
      .limit(12)
      .populate('author', 'username displayName avatar');
    }

    const userData = sanitizeUser(user);
    const isFollowing = requesterId ? user.followers.some(id => id.equals(requesterId)) : false;
    const followsRequester = requesterId ? user.following.some(id => id.equals(requesterId)) : false;

    res.json({
      success: true,
      status: 200,
      data: {
        user: userData,
        posts,
        isFollowing,
        followsRequester
      }
    });
  } catch (error) {
    console.error('Get user profile error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to fetch user profile'
    });
  }
});

app.post('/api/users/:id/follow', authenticateToken, async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const currentUserId = req.userId;

    if (targetUserId === currentUserId.toString()) {
      return res.status(400).json({
        success: false,
        status: 400,
        error: 'Cannot follow yourself'
      });
    }

    const targetUser = await User.findById(targetUserId);
    const currentUser = await User.findById(currentUserId);

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'User not found'
      });
    }

    const isFollowing = currentUser.following.some(id => id.equals(targetUserId));

    if (isFollowing) {
      // Unfollow
      currentUser.following = currentUser.following.filter(id => !id.equals(targetUserId));
      targetUser.followers = targetUser.followers.filter(id => !id.equals(currentUserId));
    } else {
      // Follow (or request if private)
      if (targetUser.isPrivate) {
        // TODO: Implement follow request system
        // For now, treat as immediate follow
      }
      currentUser.following.push(targetUserId);
      targetUser.followers.push(currentUserId);

      // Create notification
      const notification = new Notification({
        recipient: targetUserId,
        actor: currentUserId,
        type: 'follow'
      });
      await notification.save();

      // Emit socket event if user is online
      io.to(`user:${targetUserId}`).emit('notification', {
        type: 'follow',
        actor: sanitizeUser(currentUser)
      });
    }

    await currentUser.save();
    await targetUser.save();

    res.json({
      success: true,
      status: 200,
      data: {
        following: !isFollowing,
        followersCount: targetUser.followers.length
      }
    });
  } catch (error) {
    console.error('Follow error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to follow/unfollow user'
    });
  }
});

app.post('/api/users/:id/block', authenticateToken, async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const currentUserId = req.userId;

    if (targetUserId === currentUserId.toString()) {
      return res.status(400).json({
        success: false,
        status: 400,
        error: 'Cannot block yourself'
      });
    }

    const currentUser = await User.findById(currentUserId);
    const targetUser = await User.findById(targetUserId);

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'User not found'
      });
    }

    const isBlocked = currentUser.blockedUsers.some(id => id.equals(targetUserId));

    if (isBlocked) {
      // Unblock
      currentUser.blockedUsers = currentUser.blockedUsers.filter(id => !id.equals(targetUserId));
    } else {
      // Block
      currentUser.blockedUsers.push(targetUserId);
      
      // Remove mutual follows
      currentUser.following = currentUser.following.filter(id => !id.equals(targetUserId));
      currentUser.followers = currentUser.followers.filter(id => !id.equals(targetUserId));
      targetUser.following = targetUser.following.filter(id => !id.equals(currentUserId));
      targetUser.followers = targetUser.followers.filter(id => !id.equals(currentUserId));
      
      await targetUser.save();
    }

    await currentUser.save();

    res.json({
      success: true,
      status: 200,
      data: { blocked: !isBlocked }
    });
  } catch (error) {
    console.error('Block error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to block/unblock user'
    });
  }
});

// ============================================================================
// SEARCH ROUTES
// ============================================================================

app.get('/api/search', async (req, res) => {
  try {
    const { q, type = 'users', page = 1, limit = 20 } = req.query;

    if (!q || q.trim().length === 0) {
      return res.json({
        success: true,
        status: 200,
        data: { results: [], page: 1, totalPages: 0 }
      });
    }

    const query = q.trim();
    const skip = (parseInt(page) - 1) * parseInt(limit);

    let results = [];
    let total = 0;

    if (type === 'users') {
      const searchRegex = new RegExp(query, 'i');
      results = await User.find({
        $or: [
          { username: searchRegex },
          { displayName: searchRegex }
        ]
      })
      .select('-password')
      .limit(parseInt(limit))
      .skip(skip);
      
      total = await User.countDocuments({
        $or: [
          { username: searchRegex },
          { displayName: searchRegex }
        ]
      });
      
      results = results.map(sanitizeUser);
    } else if (type === 'posts') {
      const searchRegex = new RegExp(query, 'i');
      results = await Post.find({
        $or: [
          { caption: searchRegex },
          { hashtags: query.toLowerCase() }
        ],
        visibility: 'public'
      })
      .populate('author', 'username displayName avatar')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);
      
      total = await Post.countDocuments({
        $or: [
          { caption: searchRegex },
          { hashtags: query.toLowerCase() }
        ],
        visibility: 'public'
      });
    } else if (type === 'hashtags') {
      const hashtag = query.replace('#', '').toLowerCase();
      results = await Post.aggregate([
        { $match: { hashtags: hashtag, visibility: 'public' } },
        { $group: { _id: null, count: { $sum: 1 } } }
      ]);
      
      const posts = await Post.find({ hashtags: hashtag, visibility: 'public' })
        .populate('author', 'username displayName avatar')
        .sort({ createdAt: -1 })
        .limit(parseInt(limit))
        .skip(skip);
      
      results = {
        hashtag: `#${hashtag}`,
        postCount: results[0]?.count || 0,
        posts
      };
    }

    res.json({
      success: true,
      status: 200,
      data: {
        results,
        page: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Search failed'
    });
  }
});

// ============================================================================
// MEDIA ROUTES (Cloudinary Integration)
// ============================================================================

app.get('/api/media/sign', authenticateToken, async (req, res) => {
  try {
    const { filename, resource_type = 'auto' } = req.query;
    const timestamp = Math.round(Date.now() / 1000);
    const folder = resource_type === 'video' ? 'inodes/videos' : 'inodes/images';

    const params = {
      timestamp,
      folder,
      upload_preset: 'inodes_unsigned' // Create this in Cloudinary dashboard
    };

    const signature = cloudinary.utils.api_sign_request(
      params,
      process.env.CLOUDINARY_API_SECRET
    );

    res.json({
      success: true,
      status: 200,
      data: {
        signature,
        timestamp,
        cloudName: process.env.CLOUDINARY_CLOUD_NAME,
        apiKey: process.env.CLOUDINARY_API_KEY,
        folder,
        upload_preset: params.upload_preset
      }
    });
  } catch (error) {
    console.error('Sign error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to generate signature'
    });
  }
});

app.post('/api/media/confirm', authenticateToken, async (req, res) => {
  try {
    const { publicId, url, width, height, duration, format, resourceType } = req.body;

    // Verify the asset exists in Cloudinary
    try {
      await cloudinary.api.resource(publicId, { resource_type: resourceType || 'image' });
    } catch (err) {
      return res.status(400).json({
        success: false,
        status: 400,
        error: 'Invalid media reference'
      });
    }

    res.json({
      success: true,
      status: 200,
      data: {
        publicId,
        url,
        type: resourceType === 'video' ? 'video' : 'image',
        width,
        height,
        duration
      }
    });
  } catch (error) {
    console.error('Media confirm error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to confirm media'
    });
  }
});

// ============================================================================
// POST ROUTES
// ============================================================================

app.post('/api/posts', authenticateToken, upload.array('media', 10), async (req, res) => {
  try {
    const { caption, visibility = 'public' } = req.body;
    const mediaItems = [];

    // Upload media files to Cloudinary
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        const isVideo = file.mimetype.startsWith('video/');
        const folder = isVideo ? 'inodes/posts/videos' : 'inodes/posts/images';
        
        const uploadResult = await new Promise((resolve, reject) => {
          const uploadStream = cloudinary.uploader.upload_stream(
            {
              folder,
              resource_type: isVideo ? 'video' : 'image',
              transformation: isVideo ? [] : [
                { width: 1080, height: 1080, crop: 'limit', quality: 'auto' }
              ]
            },
            (error, result) => {
              if (error) reject(error);
              else resolve(result);
            }
          );
          uploadStream.end(file.buffer);
        });

        mediaItems.push({
          url: uploadResult.secure_url,
          publicId: uploadResult.public_id,
          type: isVideo ? 'video' : 'image',
          width: uploadResult.width,
          height: uploadResult.height,
          duration: uploadResult.duration
        });
      }
    }

    // Extract hashtags and mentions
    const hashtags = caption ? extractHashtags(caption) : [];
    const mentionUsernames = caption ? extractMentions(caption) : [];
    
    // Find mentioned users
    const mentionedUsers = await User.find({
      username: { $in: mentionUsernames }
    }).select('_id');

    const post = new Post({
      author: req.userId,
      caption: caption || '',
      media: mediaItems,
      visibility,
      hashtags,
      mentions: mentionedUsers.map(u => u._id)
    });

    await post.save();
    await post.populate('author', 'username displayName avatar isVerified');

    // Create notifications for mentions
    for (const mentionedUser of mentionedUsers) {
      if (!mentionedUser._id.equals(req.userId)) {
        const notification = new Notification({
          recipient: mentionedUser._id,
          actor: req.userId,
          type: 'mention',
          source: { postId: post._id }
        });
        await notification.save();

        io.to(`user:${mentionedUser._id}`).emit('notification', {
          type: 'mention',
          post: post
        });
      }
    }

    // Emit to followers' feeds
    const author = await User.findById(req.userId);
    for (const followerId of author.followers) {
      io.to(`user:${followerId}`).emit('post_created', { post });
    }

    res.status(201).json({
      success: true,
      status: 201,
      data: post
    });
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to create post'
    });
  }
});

app.get('/api/posts', async (req, res) => {
  try {
    const { page = 1, limit = 20, feedType = 'home', userId: targetUserId } = req.query;
    const requesterId = req.userId;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    let query = {};
    let sort = { createdAt: -1 };

    if (feedType === 'home' && requesterId) {
      const user = await User.findById(requesterId);
      query = {
        $or: [
          { author: { $in: user.following } },
          { author: requesterId }
        ],
        visibility: { $in: ['public', 'followers'] }
      };
    } else if (feedType === 'explore') {
      query = { visibility: 'public' };
      // For explore, we could implement recommendation logic here
      // For now, show popular posts (by likes)
      sort = { likesCount: -1, createdAt: -1 };
    } else if (feedType === 'user' && targetUserId) {
      query = { author: targetUserId };
      if (!requesterId || requesterId !== targetUserId) {
        query.visibility = { $in: ['public', 'followers'] };
      }
    } else {
      query = { visibility: 'public' };
    }

    const posts = await Post.find(query)
      .sort(sort)
      .limit(parseInt(limit))
      .skip(skip)
      .populate('author', 'username displayName avatar isVerified')
      .populate('mentions', 'username displayName');

    const total = await Post.countDocuments(query);

    // Enrich posts with user-specific data
    const enrichedPosts = posts.map(post => {
      const postObj = post.toObject();
      postObj.isLiked = requesterId ? post.likes.some(id => id.equals(requesterId)) : false;
      postObj.commentsCount = post.comments.length;
      return postObj;
    });

    res.json({
      success: true,
      status: 200,
      data: {
        posts: enrichedPosts,
        page: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        total
      }
    });
  } catch (error) {
    console.error('Fetch posts error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to fetch posts'
    });
  }
});

app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.userId;

    const post = await Post.findById(postId);
    
    if (!post) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'Post not found'
      });
    }

    const likeIndex = post.likes.findIndex(id => id.equals(userId));
    let liked = false;

    if (likeIndex >= 0) {
      // Unlike
      post.likes.splice(likeIndex, 1);
      post.likesCount = Math.max(0, post.likesCount - 1);
    } else {
      // Like
      post.likes.push(userId);
      post.likesCount += 1;
      liked = true;

      // Create notification for post author
      if (!post.author.equals(userId)) {
        const notification = new Notification({
          recipient: post.author,
          actor: userId,
          type: 'like',
          source: { postId: post._id }
        });
        await notification.save();

        io.to(`user:${post.author}`).emit('notification', {
          type: 'like',
          postId: post._id
        });
      }
    }

    await post.save();

    res.json({
      success: true,
      status: 200,
      data: {
        liked,
        likesCount: post.likesCount
      }
    });
  } catch (error) {
    console.error('Like post error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to like post'
    });
  }
});

app.post('/api/posts/:id/comment', authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;
    const { text } = req.body;

    if (!text || text.trim().length === 0) {
      return res.status(400).json({
        success: false,
        status: 400,
        error: 'Comment text is required'
      });
    }

    const post = await Post.findById(postId);
    
    if (!post) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'Post not found'
      });
    }

    const comment = {
      user: req.userId,
      text: text.trim(),
      createdAt: new Date()
    };

    post.comments.push(comment);
    await post.save();

    await post.populate('comments.user', 'username displayName avatar');

    // Create notification for post author
    if (!post.author.equals(req.userId)) {
      const notification = new Notification({
        recipient: post.author,
        actor: req.userId,
        type: 'comment',
        source: { postId: post._id },
        payload: { commentText: text.substring(0, 100) }
      });
      await notification.save();

      io.to(`user:${post.author}`).emit('notification', {
        type: 'comment',
        postId: post._id
      });
    }

    res.status(201).json({
      success: true,
      status: 201,
      data: comment
    });
  } catch (error) {
    console.error('Comment error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to add comment'
    });
  }
});

app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;
    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'Post not found'
      });
    }

    // Check authorization
    const user = await User.findById(req.userId);
    if (!post.author.equals(req.userId) && user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        status: 403,
        error: 'Not authorized to delete this post'
      });
    }

    // Delete media from Cloudinary
    for (const media of post.media) {
      if (media.publicId) {
        try {
          await cloudinary.uploader.destroy(media.publicId, {
            resource_type: media.type === 'video' ? 'video' : 'image'
          });
        } catch (err) {
          console.error('Error deleting media:', err);
        }
      }
    }

    await Post.findByIdAndDelete(postId);

    res.json({
      success: true,
      status: 200,
      data: { message: 'Post deleted successfully' }
    });
  } catch (error) {
    console.error('Delete post error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to delete post'
    });
  }
});

// ============================================================================
// STORY ROUTES
// ============================================================================

app.post('/api/stories', authenticateToken, upload.single('media'), async (req, res) => {
  try {
    const { visibility } = req.body;

    if (!req.file) {
      return res.status(400).json({
        success: false,
        status: 400,
        error: 'Media file is required for stories'
      });
    }

    const isVideo = req.file.mimetype.startsWith('video/');
    const folder = isVideo ? 'inodes/stories/videos' : 'inodes/stories/images';

    // Upload to Cloudinary
    const uploadResult = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder,
          resource_type: isVideo ? 'video' : 'image',
          transformation: isVideo ? [] : [
            { width: 1080, height: 1920, crop: 'limit', quality: 'auto' }
          ]
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );
      uploadStream.end(req.file.buffer);
    });

    // Get user's default story privacy
    const user = await User.findById(req.userId);
    const storyVisibility = visibility || user.settings.storyPrivacy;

    const story = new Story({
      author: req.userId,
      media: {
        url: uploadResult.secure_url,
        publicId: uploadResult.public_id,
        type: isVideo ? 'video' : 'image'
      },
      visibility: storyVisibility,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
    });

    await story.save();
    await story.populate('author', 'username displayName avatar isVerified');

    // Emit to followers
    for (const followerId of user.followers) {
      io.to(`user:${followerId}`).emit('story_added', { story });
    }

    res.status(201).json({
      success: true,
      status: 201,
      data: story
    });
  } catch (error) {
    console.error('Create story error:', error);
    res.status(500).json({
      success: false,
      status: 500,
      error: 'Failed to create story'
    });
  }
});

app.get('/api/stories', authenticateToken, async (req, res) => {
  try {
    const userId = req.userId;
    const user = await User.findById(userId);

    // Safety defaults
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    user.following = user.following || [];
    user.blockedUsers = user.blockedUsers || [];

    const viewableUserIds = [...user.following, userId];

    const stories = await Story.find({
      author: { $in: viewableUserIds },
      expiresAt: { $gt: new Date() },
      archived: false
    })
      .populate('author', 'username displayName avatar isVerified followers')
      .sort({ createdAt: -1 });

    const filteredStories = stories.filter(story => {
      const author = story.author;
      if (!author) return false;

      // Safe access
      const blockedUsers = user.blockedUsers || [];
      if (blockedUsers.some(id => id.equals(author._id))) return false;

      const authorFollowers = author.followers || [];
      if (story.visibility === 'public') return true;
      if (story.visibility === 'followers' && authorFollowers.some(id => id.equals(userId))) {
        return true;
      }
      if (author._id.equals(userId)) return true;
      return false;
    });

    const groupedStories = {};
    filteredStories.forEach(story => {
      const authorId = story.author._id.toString();
      if (!groupedStories[authorId]) {
        groupedStories[authorId] = {
          author: story.author,
          stories: [],
          hasUnseen: false
        };
      }

      const viewers = story.viewers || [];
      const hasSeen = viewers.some(id => id.equals(userId));
      groupedStories[authorId].stories.push({
        ...story.toObject(),
        hasSeen
      });
      if (!hasSeen) groupedStories[authorId].hasUnseen = true;
    });

    res.json({ success: true, status: 200, data: Object.values(groupedStories) });
  } catch (error) {
    console.error('Fetch stories error:', error);
    res.status(500).json({ success: false, status: 500, error: 'Failed to fetch stories' });
  }
});


app.post('/api/stories/:id/view', authenticateToken, async (req, res) => {
  try {
    const storyId = req.params.id;
    const userId = req.userId;

    const story = await Story.findById(storyId);

    if (!story) {
      return res.status(404).json({
        success: false,
        status: 404,
        error: 'Story not found'
      });
    }

    // Check if already viewed
    if (!story.viewers.some(id => id.equals(userId))) {
      story.viewers.push(userId);
      await story.save();

      // Don't notify for every view - batch notifications
      // For demo purposes, we'll emit but in production use batching
      if (!story.author.equals(userId)) {
        io.to(`user:${story.author}`).emit('story_view', {
          storyId: story._id,
          viewerId: userId
        });
      }
    }

        res.json({
      success: true,
      status: 200
    });
  } catch (error) {
    console.error('Story view error:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// ============================================================================
// ROOT ROUTE - Serve Frontend
// ============================================================================

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});