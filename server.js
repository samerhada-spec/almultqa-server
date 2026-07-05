const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: { origin: '*' }
});

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ==================== الأمان والتشفير ====================
// باسورد الأدمن القوي (مشفر بـ SHA-256)
const ADMIN_PASSWORD_HASH = '8c6e2e6f3e7a5b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c';
const ADMIN_RECOVERY_CODE = 'MLQ-8X7K-9M2P-5R6T-4W3Q';
const ADMIN_RECOVERY_HASH = crypto.createHash('sha256').update(ADMIN_RECOVERY_CODE).digest('hex');

// ملفات البيانات (تخزن على الخادم فقط، وليس داخل APK)
const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const MESSAGES_FILE = path.join(__dirname, 'data', 'messages.json');
const ADMIN_LOGS_FILE = path.join(__dirname, 'data', 'admin_logs.json');
const BACKUP_DIR = path.join(__dirname, 'backups');

// إنشاء المجلدات إذا لم توجد
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
}
if (!fs.existsSync(BACKUP_DIR)) {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

// البيانات الافتراضية للمستخدمين
const defaultUsers = {
  "admin": {
    "userId": "admin",
    "username": "admin",
    "fullName": "مدير التطبيق",
    "passwordHash": ADMIN_PASSWORD_HASH,
    "recoveryCode": ADMIN_RECOVERY_HASH,
    "role": "admin",
    "createdAt": new Date().toISOString(),
    "isOnline": false,
    "lastLogin": null
  },
  "ahmed": {
    "userId": "ahmed",
    "username": "ahmed",
    "fullName": "أحمد محمد",
    "passwordHash": crypto.createHash('sha256').update("user123456").digest('hex'),
    "recoveryCode": crypto.createHash('sha256').update("MLQ-USER-AH12").digest('hex'),
    "role": "user",
    "createdAt": new Date().toISOString(),
    "isOnline": false,
    "lastLogin": null
  },
  "sara": {
    "userId": "sara",
    "username": "sara",
    "fullName": "سارة خالد",
    "passwordHash": crypto.createHash('sha256').update("user123456").digest('hex'),
    "recoveryCode": crypto.createHash('sha256').update("MLQ-USER-SA56").digest('hex'),
    "role": "user",
    "createdAt": new Date().toISOString(),
    "isOnline": false,
    "lastLogin": null
  }
};

// تحميل أو إنشاء الملفات
function loadData() {
  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
  }
  if (!fs.existsSync(MESSAGES_FILE)) {
    fs.writeFileSync(MESSAGES_FILE, JSON.stringify({}, null, 2));
  }
  if (!fs.existsSync(ADMIN_LOGS_FILE)) {
    fs.writeFileSync(ADMIN_LOGS_FILE, JSON.stringify([], null, 2));
  }
}

loadData();

let users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
let messages = JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8'));
let adminLogs = JSON.parse(fs.readFileSync(ADMIN_LOGS_FILE, 'utf8'));
let connectedUsers = new Map();

// ==================== دوال مساعدة ====================
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function addAdminLog(action, userId, details = {}) {
  adminLogs.unshift({
    id: Date.now(),
    action,
    userId,
    details,
    timestamp: new Date().toISOString(),
    ip: null
  });
  // الاحتفاظ بآخر 1000 سجل فقط
  if (adminLogs.length > 1000) adminLogs = adminLogs.slice(0, 1000);
  fs.writeFileSync(ADMIN_LOGS_FILE, JSON.stringify(adminLogs, null, 2));
}

function createBackup() {
  const backupName = `backup_${Date.now()}.json`;
  const backupPath = path.join(BACKUP_DIR, backupName);
  const backupData = {
    users,
    messages,
    adminLogs,
    timestamp: new Date().toISOString()
  };
  fs.writeFileSync(backupPath, JSON.stringify(backupData, null, 2));
  console.log(`✅ تم إنشاء نسخة احتياطية: ${backupName}`);
  
  // حذف النسخ القديمة (احتفظ بآخر 10 نسخ فقط)
  const backups = fs.readdirSync(BACKUP_DIR).filter(f => f.endsWith('.json'));
  if (backups.length > 10) {
    backups.sort().slice(0, -10).forEach(f => {
      fs.unlinkSync(path.join(BACKUP_DIR, f));
    });
  }
}

// ==================== API Routes ====================

// تسجيل الدخول العادي
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = Object.values(users).find(u => u.username === username);
  
  if (!user || user.passwordHash !== hashPassword(password)) {
    addAdminLog('LOGIN_FAILED', username, { reason: 'Invalid credentials' });
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  }
  
  // تحديث آخر تسجيل دخول
  users[user.userId].lastLogin = new Date().toISOString();
  users[user.userId].isOnline = true;
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  
  addAdminLog('LOGIN_SUCCESS', user.userId, { role: user.role });
  
  res.json({
    success: true,
    userId: user.userId,
    fullName: user.fullName,
    role: user.role
  });
});

// تسجيل الدخول الخاص بالأدمن (بكلمة مرور قوية)
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  
  if (hashPassword(password) !== ADMIN_PASSWORD_HASH) {
    addAdminLog('ADMIN_LOGIN_FAILED', 'unknown', { reason: 'Invalid admin password' });
    return res.status(401).json({ error: 'كلمة مرور الأدمن غير صحيحة' });
  }
  
  // تحديث حالة الأدمن
  if (users['admin']) {
    users['admin'].lastLogin = new Date().toISOString();
    users['admin'].isOnline = true;
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  }
  
  addAdminLog('ADMIN_LOGIN_SUCCESS', 'admin', {});
  
  // إنشاء توكن جلسة
  const sessionToken = crypto.randomBytes(32).toString('hex');
  
  res.json({
    success: true,
    token: sessionToken,
    fullName: users['admin']?.fullName || 'مدير التطبيق'
  });
});

// استعادة الحساب بكود الاستعادة
app.post('/api/recover', (req, res) => {
  const { username, recoveryCode } = req.body;
  const user = Object.values(users).find(u => u.username === username);
  
  if (!user || user.recoveryCode !== hashPassword(recoveryCode)) {
    addAdminLog('RECOVER_FAILED', username, { reason: 'Invalid recovery code' });
    return res.status(401).json({ error: 'كود الاستعادة غير صحيح' });
  }
  
  addAdminLog('RECOVER_SUCCESS', user.userId, {});
  
  res.json({
    success: true,
    userId: user.userId,
    fullName: user.fullName
  });
});

// إعادة تعيين كلمة المرور (عبر كود الاستعادة)
app.post('/api/reset-password', (req, res) => {
  const { username, recoveryCode, newPassword } = req.body;
  const user = Object.values(users).find(u => u.username === username);
  
  if (!user || user.recoveryCode !== hashPassword(recoveryCode)) {
    return res.status(401).json({ error: 'كود الاستعادة غير صحيح' });
  }
  
  // تحديث كلمة المرور
  users[user.userId].passwordHash = hashPassword(newPassword);
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  
  addAdminLog('PASSWORD_RESET', user.userId, {});
  
  res.json({ success: true });
});

// إنشاء حساب جديد
app.post('/api/register', (req, res) => {
  const { userId, username, fullName, password } = req.body;
  
  if (users[userId]) {
    return res.status(400).json({ error: 'المستخدم موجود مسبقاً' });
  }
  
  const recoveryCode = `MLQ-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  
  users[userId] = {
    userId,
    username,
    fullName,
    passwordHash: hashPassword(password),
    recoveryCode: hashPassword(recoveryCode),
    role: 'user',
    createdAt: new Date().toISOString(),
    isOnline: false,
    lastLogin: null
  };
  
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  addAdminLog('USER_REGISTERED', userId, {});
  createBackup(); // إنشاء نسخة احتياطية بعد إضافة مستخدم جديد
  
  res.json({ success: true, recoveryCode });
});

// الحصول على جميع المستخدمين (للأدمن فقط)
app.get('/api/admin/users', (req, res) => {
  const adminToken = req.headers['x-admin-token'];
  
  // التحقق من توكن الأدمن
  if (!adminToken || adminToken !== hashPassword(ADMIN_PASSWORD_HASH)) {
    return res.status(403).json({ error: 'غير مصرح بالوصول' });
  }
  
  const userList = Object.values(users).map(u => ({
    userId: u.userId,
    username: u.username,
    fullName: u.fullName,
    isOnline: connectedUsers.has(u.userId),
    role: u.role,
    createdAt: u.createdAt,
    lastLogin: u.lastLogin
  }));
  
  addAdminLog('ADMIN_VIEW_USERS', 'admin', { count: userList.length });
  res.json(userList);
});

// الحصول على جميع المستخدمين (للمستخدمين العاديين - بدون معلومات حساسة)
app.get('/api/users', (req, res) => {
  const userList = Object.values(users)
    .filter(u => u.userId !== 'admin') // لا تظهر الأدمن للمستخدمين العاديين
    .map(u => ({
      userId: u.userId,
      username: u.username,
      fullName: u.fullName,
      isOnline: connectedUsers.has(u.userId),
    }));
  
  res.json(userList);
});

// حظر مستخدم (للأدمن فقط)
app.post('/api/admin/block', (req, res) => {
  const adminToken = req.headers['x-admin-token'];
  const { userId } = req.body;
  
  if (!adminToken || adminToken !== hashPassword(ADMIN_PASSWORD_HASH)) {
    return res.status(403).json({ error: 'غير مصرح بالوصول' });
  }
  
  if (users[userId]) {
    users[userId].isBlocked = true;
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    addAdminLog('USER_BLOCKED', 'admin', { blockedUser: userId });
    
    // قطع اتصال المستخدم إذا كان متصلاً
    const socketId = connectedUsers.get(userId);
    if (socketId) {
      io.to(socketId).emit('account_blocked');
      io.sockets.sockets.get(socketId)?.disconnect();
      connectedUsers.delete(userId);
    }
  }
  
  res.json({ success: true });
});

// إلغاء حظر مستخدم
app.post('/api/admin/unblock', (req, res) => {
  const adminToken = req.headers['x-admin-token'];
  const { userId } = req.body;
  
  if (!adminToken || adminToken !== hashPassword(ADMIN_PASSWORD_HASH)) {
    return res.status(403).json({ error: 'غير مصرح بالوصول' });
  }
  
  if (users[userId]) {
    delete users[userId].isBlocked;
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    addAdminLog('USER_UNBLOCKED', 'admin', { unblockedUser: userId });
  }
  
  res.json({ success: true });
});

// إرسال إشعار لجميع المستخدمين
app.post('/api/admin/send-notification', (req, res) => {
  const adminToken = req.headers['x-admin-token'];
  const { message, type } = req.body;
  
  if (!adminToken || adminToken !== hashPassword(ADMIN_PASSWORD_HASH)) {
    return res.status(403).json({ error: 'غير مصرح بالوصول' });
  }
  
  // إرسال الإشعار لجميع المستخدمين المتصلين
  for (const [userId, socketId] of connectedUsers.entries()) {
    if (userId !== 'admin') {
      io.to(socketId).emit('admin_notification', { message, type, timestamp: new Date().toISOString() });
    }
  }
  
  addAdminLog('SENT_NOTIFICATION', 'admin', { message: message.substring(0, 50) });
  res.json({ success: true });
});

// الحصول على سجلات الأدمن
app.get('/api/admin/logs', (req, res) => {
  const adminToken = req.headers['x-admin-token'];
  
  if (!adminToken || adminToken !== hashPassword(ADMIN_PASSWORD_HASH)) {
    return res.status(403).json({ error: 'غير مصرح بالوصول' });
  }
  
  res.json(adminLogs.slice(0, 100));
});

// إنشاء نسخة احتياطية يدوية
app.post('/api/admin/backup', (req, res) => {
  const adminToken = req.headers['x-admin-token'];
  
  if (!adminToken || adminToken !== hashPassword(ADMIN_PASSWORD_HASH)) {
    return res.status(403).json({ error: 'غير مصرح بالوصول' });
  }
  
  createBackup();
  addAdminLog('MANUAL_BACKUP', 'admin', {});
  res.json({ success: true, message: 'تم إنشاء النسخة الاحتياطية' });
});

// الحصول على إحصائيات التطبيق
app.get('/api/admin/stats', (req, res) => {
  const adminToken = req.headers['x-admin-token'];
  
  if (!adminToken || adminToken !== hashPassword(ADMIN_PASSWORD_HASH)) {
    return res.status(403).json({ error: 'غير مصرح بالوصول' });
  }
  
  const totalUsers = Object.keys(users).length;
  const onlineUsers = connectedUsers.size;
  const totalMessages = Object.values(messages).reduce((sum, arr) => sum + arr.length, 0);
  
  res.json({
    totalUsers,
    onlineUsers,
    totalMessages,
    serverUptime: process.uptime(),
    lastBackup: fs.readdirSync(BACKUP_DIR).sort().pop() || null
  });
});

// ==================== Socket.IO ====================

io.on('connection', (socket) => {
  console.log('🟢 مستخدم جديد اتصل');
  
  let currentUserId = null;
  
  socket.on('register', (userId) => {
    // التحقق من عدم حظر المستخدم
    if (users[userId]?.isBlocked) {
      socket.emit('account_blocked');
      socket.disconnect();
      return;
    }
    
    currentUserId = userId;
    connectedUsers.set(userId, socket.id);
    
    if (users[userId]) {
      users[userId].isOnline = true;
      fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    }
    
    console.log(`✅ ${userId} أصبح متصلاً`);
    io.emit('user_status', { userId, status: 'online' });
  });
  
  // إرسال رسالة
  socket.on('send_message', (data) => {
    const { targetId, message, senderId } = data;
    
    // التحقق من حظر المستخدم
    if (users[senderId]?.isBlocked) {
      socket.emit('message_blocked');
      return;
    }
    
    // حفظ الرسالة
    if (!messages[targetId]) messages[targetId] = [];
    messages[targetId].push({
      id: Date.now(),
      text: message,
      senderId: senderId,
      timestamp: new Date().toISOString(),
      status: 'sent'
    });
    fs.writeFileSync(MESSAGES_FILE, JSON.stringify(messages, null, 2));
    
    // إرسال للمستقبل
    const targetSocket = connectedUsers.get(targetId);
    if (targetSocket && !users[targetId]?.isBlocked) {
      io.to(targetSocket).emit('new_message', {
        message: message,
        senderId: senderId,
        timestamp: new Date().toISOString()
      });
    }
  });
  
  // طلب مكالمة
  socket.on('call_request', (data) => {
    const { targetId, callerId, isVideo } = data;
    
    if (users[callerId]?.isBlocked) {
      socket.emit('call_blocked');
      return;
    }
    
    const targetSocket = connectedUsers.get(targetId);
    if (targetSocket && !users[targetId]?.isBlocked) {
      io.to(targetSocket).emit('call_request', { callerId, isVideo });
    }
  });
  
  socket.on('call_accept', (data) => {
    const { callerId } = data;
    const callerSocket = connectedUsers.get(callerId);
    if (callerSocket) {
      io.to(callerSocket).emit('call_accepted');
    }
  });
  
  socket.on('call_reject', (data) => {
    const { callerId } = data;
    const callerSocket = connectedUsers.get(callerId);
    if (callerSocket) {
      io.to(callerSocket).emit('call_rejected');
    }
  });
  
  socket.on('disconnect', () => {
    if (currentUserId) {
      connectedUsers.delete(currentUserId);
      if (users[currentUserId]) {
        users[currentUserId].isOnline = false;
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
      }
      console.log(`🔴 ${currentUserId} غير متصل`);
      io.emit('user_status', { userId: currentUserId, status: 'offline' });
    }
  });
});

// نسخة احتياطية تلقائية كل 24 ساعة
setInterval(() => {
  createBackup();
}, 24 * 60 * 60 * 1000);

// تشغيل الخادم
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║     🚀 خادم الملتقى يعمل بنجاح!                                   ║
║                                                                    ║
║     📡 المنفذ: ${PORT}                                                ║
║     🌐 IP: http://${getLocalIp()}:${PORT}                            ║
║                                                                    ║
║     🔐 بيانات الدخول:                                              ║
║        👑 الأدمن: admin                                           ║
║        🔑 كلمة مرور الأدمن: ${ADMIN_PASSWORD_HASH.substring(0,20)}...  ║
║        🔐 كود الاستعادة: ${ADMIN_RECOVERY_CODE}                       ║
║                                                                    ║
║     👤 مستخدمين تجريبيين:                                          ║
║        - ahmed / 123456                                           ║
║        - sara / 123456                                            ║
║                                                                    ║
║     📁 مسار البيانات: ${path.join(__dirname, 'data')}                ║
║     💾 النسخ الاحتياطية: ${BACKUP_DIR}                               ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
  `);
});

function getLocalIp() {
  const { networkInterfaces } = require('os');
  const nets = networkInterfaces();
  
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return '127.0.0.1';
}