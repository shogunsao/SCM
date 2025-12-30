import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy'; 
import QRCode from 'qrcode';       

const app = express();
const PORT = 5000;
const JWT_SECRET = 'super_secret_key_change_this';

// 1. CONFIG
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// --- CLOUDINARY CONFIG ---
cloudinary.config({
    cloud_name: 'dcreily3l', 
    api_key: '644213573533415', 
    api_secret: 'ONABORM8BAwtApxp7UiZLqIiku0' 
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'scm_uploads',
        resource_type: 'auto', 
    },
});

const upload = multer({ storage: storage }).any();

// --- 2. DATABASE SCHEMAS ---

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'employee' },
  isActive: { type: Boolean, default: true },
  twoFASecret: { type: Object }, 
  isTwoFAEnabled: { type: Boolean, default: false }, 
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

const LoanRequestSchema = new mongoose.Schema({
  selectedProduct: String, amount: Number, term: Number, purpose: String, repaymentSource: String, collateralType: String, userType: String,
  lastname: String, firstname: String, regNo: String, phone: String, email: String, address: String,
  orgName: String, orgRegNo: String, contactName: String, contactPosition: String, contactPhone: String,
  hasCoBorrower: Boolean, coLastname: String, coFirstname: String, coRegNo: String, coPhone: String,
  selfieUrl: String, fileNames: [String],
  status: { type: String, default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});
const LoanRequest = mongoose.models.LoanRequest || mongoose.model('LoanRequest', LoanRequestSchema);

const TrustRequestSchema = new mongoose.Schema({
    lastname: String, firstname: String, phone: String, email: String, amount: String, 
    status: { type: String, default: 'pending' }, contactNote: String, 
    createdAt: { type: Date, default: Date.now }
});
const TrustRequest = mongoose.models.TrustRequest || mongoose.model('TrustRequest', TrustRequestSchema);

const LogSchema = new mongoose.Schema({
    userName: String, userRole: String, action: String, details: String,
    date: { type: Date, default: Date.now }
});
const Log = mongoose.models.Log || mongoose.model('Log', LogSchema);

// --- 3. CONNECT DB (Atlas Cloud) ---
// ✅ Таны MongoDB Atlas холбоос
const MONGO_URI = 'mongodb+srv://otgonbilegtseden_db_user:uFE1QiJHzhovsslQ@cluster0.izqptda.mongodb.net/scm_db?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGO_URI)
  .then(async () => {
      console.log('✅ MongoDB Atlas Connected!');
      
      // Админ шалгах логик (Cloud дээр шинээр үүснэ)
      const adminExists = await User.findOne({ email: 'admin@scm.mn' });
      if (!adminExists) {
          const hashedPassword = await bcrypt.hash('admin123', 10);
          await new User({ 
              name: 'Super Admin', 
              email: 'admin@scm.mn', 
              password: hashedPassword, 
              role: 'admin',
              isActive: true,
              isTwoFAEnabled: false 
          }).save();
          console.log('👑 Admin created on Cloud DB');
      }
  })
  .catch(err => console.error('❌ DB Error:', err));

const createLog = async (user, action, details) => {
    try {
        if(user) await new Log({ userName: user.name, userRole: user.role, action, details }).save();
    } catch (e) { console.error("Log error", e); }
};

// --- 4. ROUTES ---

// LOGIN (✅ 2FA & Time Window Fix)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, token: twoFAToken } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) return res.status(400).json({ message: 'Хэрэглэгч олдсонгүй.' });
        if (user.isActive === false) return res.status(403).json({ message: 'Таны эрхийг түр хаасан байна.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Нууц үг буруу.' });

        // ✅ 2FA Logic
        if (user.isTwoFAEnabled) {
            if (!twoFAToken) {
                return res.json({ require2FA: true, userId: user._id }); 
            }
            const verified = speakeasy.totp.verify({
                secret: user.twoFASecret.base32,
                encoding: 'base32',
                token: twoFAToken,
                window: 1 // 30 секундын зөрүүг зөвшөөрнө
            });
            if (!verified) {
                return res.status(400).json({ message: 'Authenticator код буруу байна.' });
            }
        }

        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
        await createLog(user, 'Нэвтэрсэн', 'Амжилттай нэвтэрлээ');
        res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

// 2FA SETUP
app.post('/api/auth/2fa/setup', async (req, res) => {
    try {
        const { userId } = req.body;
        const user = await User.findById(userId);
        const secret = speakeasy.generateSecret({ name: `SCM Admin (${user.email})` });
        user.twoFASecret = secret;
        await user.save();
        QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
            res.json({ secret: secret.base32, qrCode: data_url });
        });
    } catch (e) { res.status(500).json({ message: 'Error generating QR' }); }
});

// 2FA VERIFY (✅ Syntax Error Fixed Here)
app.post('/api/auth/2fa/verify', async (req, res) => {
    try {
        const { userId, token } = req.body;
        const user = await User.findById(userId);
        const verified = speakeasy.totp.verify({
            secret: user.twoFASecret.base32,
            encoding: 'base32',
            token: token,
            window: 1 // 30 секундын зөрүүг зөвшөөрнө
        });
        if (verified) {
            user.isTwoFAEnabled = true;
            await user.save();
            await createLog(user, '2FA Идэвхжүүлсэн', 'Google Authenticator холболоо');
            res.json({ message: 'Амжилттай идэвхжлээ!' });
        } else {
            res.status(400).json({ message: 'Код буруу байна.' });
        }
    } catch (e) { res.status(500).json({ message: 'Error verifying' }); }
});

// REGISTER & USERS
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, role, createdBy } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: 'Бүртгэлтэй имэйл байна.' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword, role: role || 'employee', isActive: true });
        await newUser.save();
        if (createdBy) await createLog(createdBy, 'Хэрэглэгч үүсгэх', `Шинэ хэрэглэгч: ${email} (${role})`);
        res.status(201).json({ message: 'Амжилттай үүслээ!' });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

app.put('/api/auth/change-password/:id', async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ message: 'User not found' });
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Хуучин нууц үг буруу' });
        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
        await createLog(user, 'Нууц үг солих', 'Нууц үг солигдлоо');
        res.json({ message: 'Success' });
    } catch (error) { res.status(500).json({ message: 'Error' }); }
});

app.get('/api/users', async (req, res) => {
    try { const users = await User.find().select('-password').sort({ createdAt: -1 }); res.json(users); } 
    catch (e) { res.status(500).json({ message: 'Error' }); }
});
app.put('/api/users/:id', async (req, res) => {
    try { 
        const { role, isActive, adminUser } = req.body;
        const user = await User.findByIdAndUpdate(req.params.id, { role, isActive }, { new: true });
        if(adminUser) await createLog(adminUser, 'Хэрэглэгч засах', `${user.email} -> ${role}, ${isActive}`);
        res.json(user);
    } catch (e) { res.status(500).json({ message: 'Error' }); }
});
app.delete('/api/users/:id', async (req, res) => {
    try { await User.findByIdAndDelete(req.params.id); res.json({ message: 'Deleted' }); } 
    catch (e) { res.status(500).json({ message: 'Error' }); }
});
app.get('/api/logs', async (req, res) => {
    try { const logs = await Log.find().sort({ date: -1 }).limit(100); res.json(logs); } 
    catch (e) { res.status(500).json({ message: 'Error' }); }
});

// LOAN ROUTES
app.post('/api/loans', (req, res) => {
    upload(req, res, async (err) => {
        if (err) {
            console.error("❌ CLOUDINARY UPLOAD ERROR:", err); 
            return res.status(500).json({ message: 'Файл хуулахад алдаа.', error: err.message });
        }
        try {
            let amount = parseInt(req.body.amount);
            if (isNaN(amount)) amount = 0;
            const fileUrls = [];
            let selfieUrl = '';
            if (req.files && req.files.length > 0) {
                req.files.forEach(file => {
                    if (file.fieldname === 'file_selfie') selfieUrl = file.path;
                    fileUrls.push(file.path);
                });
            }
            const loanData = { ...req.body, amount: amount, fileNames: fileUrls, selfieUrl: selfieUrl, hasCoBorrower: req.body.hasCoBorrower === 'true' };
            const newLoan = new LoanRequest(loanData);
            await newLoan.save();
            res.status(201).json({ message: 'Success' });
        } catch (dbError) { res.status(500).json({ message: 'Database error', error: dbError.message }); }
    });
});

app.get('/api/loans', async (req, res) => {
    try { const loans = await LoanRequest.find().sort({ createdAt: -1 }); res.json(loans); } 
    catch (e) { res.status(500).json({ message: 'Error' }); }
});
app.put('/api/loans/:id', async (req, res) => {
    try {
        const { status, adminUser } = req.body;
        const updated = await LoanRequest.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if(adminUser) await createLog(adminUser, 'Зээл шийдвэрлэх', `ID: ${req.params.id.slice(-4)}, Status: ${status}`);
        res.json(updated);
    } catch (e) { res.status(500).json({ message: 'Error' }); }
});

// TRUST ROUTES
app.post('/api/trusts', async (req, res) => {
    try {
        const newTrust = new TrustRequest(req.body);
        await newTrust.save();
        res.status(201).json({ message: 'Trust request sent!' });
    } catch (e) { res.status(500).json({ message: 'Error' }); }
});
app.get('/api/trusts', async (req, res) => {
    try { const trusts = await TrustRequest.find().sort({ createdAt: -1 }); res.json(trusts); } 
    catch (e) { res.status(500).json({ message: 'Error' }); }
});
app.put('/api/trusts/:id', async (req, res) => {
    try {
        const { contactNote, adminUser } = req.body;
        const updated = await TrustRequest.findByIdAndUpdate(req.params.id, { contactNote, status: 'contacted' }, { new: true });
        if(adminUser) await createLog(adminUser, 'Итгэлцэл холбогдох', `ID: ${req.params.id.slice(-4)}, Note: ${contactNote}`);
        res.json(updated);
    } catch (e) { res.status(500).json({ message: 'Error' }); }
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port: ${PORT}`);
});