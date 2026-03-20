import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import fs from "fs";
import path from "path";
// this creates an upload file locally later swtitch to aws
const uploadsPath = path.join(process.cwd(), "uploads");

if (!fs.existsSync(uploadsPath)) {
  fs.mkdirSync(uploadsPath);
  console.log("📁 Created uploads directory");
}


dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// ============================
// MongoDB
// ============================

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB error:", err));

// ============================
// Models
// ============================

const userSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String
});

const fileSchema = new mongoose.Schema({
  originalName: String,
  filename: String,
  size: Number,
  mimetype: String,
  userId: mongoose.Schema.Types.ObjectId,
  uploadedAt: { type: Date, default: Date.now },

  embedding: {
    type: [Number],
    default: []
  }
});

const User = mongoose.model("User", userSchema);
const File = mongoose.model("File", fileSchema);

// ============================
// JWT Middleware
// ============================

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "No token" });

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ============================
// Multer Setup
// ============================

const storage = multer.diskStorage({
  destination: "./uploads",
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + "-" + file.originalname;
    cb(null, uniqueName);
  }
});

const upload = multer({ storage });

// ============================
// Routes
// ============================

app.get("/", (req, res) => {
  res.send("Backend running 🚀");
});

// Signup
app.post("/api/auth/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Missing fields" });

  const existingUser = await User.findOne({ email });
  if (existingUser)
    return res.status(400).json({ error: "User already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await User.create({
    username,
    email,
    password: hashedPassword
  });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

  res.status(201).json({
    token,
    user: { username: user.username, email: user.email }
  });
});

// Login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "User not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: "Wrong password" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

  res.json({
    token,
    user: { username: user.username, email: user.email }
  });
});
// Get Current User
app.get("/api/auth/me", authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId).select("-password");

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  res.json({ user });
});


// Upload File
app.post("/api/files/upload", authMiddleware, upload.single("file"), async (req, res) => {
  const file = await File.create({
    originalName: req.file.originalname,
    filename: req.file.filename,
    size: req.file.size,
    mimetype: req.file.mimetype,
    userId: req.userId
  });

  res.json({ success: true, file });
});

// List Files
app.get("/api/files", authMiddleware, async (req, res) => {
  const files = await File.find({ userId: req.userId });
  res.json({ files });
});

// Download File
app.get("/api/files/:id/download", authMiddleware, async (req, res) => {
  const file = await File.findById(req.params.id);
  if (!file) return res.status(404).json({ error: "File not found" });

  res.download(`uploads/${file.filename}`, file.originalName);
});

// Delete File
app.delete("/api/files/:id", authMiddleware, async (req, res) => {
  const file = await File.findById(req.params.id);
  if (!file) return res.status(404).json({ error: "File not found" });

  fs.unlinkSync(path.join("uploads", file.filename));
  await file.deleteOne();

  res.json({ success: true });
});

// ============================
// Simple Search
// ============================

app.post("/api/search", authMiddleware, async (req, res) => {
  const { query } = req.body;

  if (!query) {
    return res.json({ results: [] });
  }

  try {
    const files = await File.find({
      userId: req.userId,
      originalName: { $regex: query, $options: "i" }
    });

    res.json({ results: files });
  } catch (err) {
    res.status(500).json({ error: "Search failed" });
  }
});

// ============================
// Start Server
// ============================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
