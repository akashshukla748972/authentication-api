import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import helmet from "helmet";
import morgan from "morgan";
import cors from "cors";
import jwt from "jsonwebtoken";

dotenv.config(); // Load environment variables
const app = express();

// Middleware
app.use(express.json());
app.use(helmet()); // Adds security headers
app.use(morgan("combined")); // Logs HTTP requests
app.use(cors()); // Handles Cross-Origin Resource Sharing

// MongoDB Connection
const connectDB = async () => {
  try {
    await mongoose.connect(
      `mongodb+srv://${process.env.USER}:${process.env.PASSWORD}@cluster0.ricpc.mongodb.net/${process.env.DB_NAME}?retryWrites=true&w=majority`
    );
    console.log("Successfully connected to database");
  } catch (error) {
    console.error("Database connection error:", error.message);
    process.exit(1); // Exit process on failure
  }
};
connectDB();

// User Schema
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
  },
});

const User = mongoose.model("User", userSchema);

// Routes
app.get("/", (req, res) => {
  res.status(200).json({
    message: "Welcome to our application!",
    success: true,
    error: false,
  });
});

app.post("/create", async (req, res) => {
  const { name, password } = req.body;
  // Validate input
  if (!name || !password) {
    return res.status(400).json({
      message: "Name and password are required",
      success: false,
      error: true,
    });
  }

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ name });
    if (existingUser) {
      return res.status(409).json({
        message: "User already exists",
        success: false,
        error: true,
      });
    }

    // Hash the password and save user
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, password: hashedPassword });
    const savedUser = await newUser.save();

    res.status(201).json({
      message: "User created successfully",
      data: savedUser,
      success: true,
      error: false,
    });
  } catch (error) {
    console.error("Error creating user:", error.message);
    res.status(500).json({
      message: "Internal server error",
      success: false,
      error: true,
    });
  }
});

app.post("/login", async (req, res) => {
  const { name, password } = req.body;

  if (!name || !password) {
    res.status(400).json({
      message: "All fields required",
      success: false,
      error: true,
    });
    return;
  }

  try {
    // check user exist
    const isExist = await User.findOne({ name });
    if (!isExist) {
      res.status(400).json({
        message: "User or Password not exist",
        success: false,
        error: true,
      });
      return;
    }

    // Compaire password
    const isEqual = await bcrypt.compare(password, isExist.password);
    if (!isEqual) {
      res.status(400).json({
        message: "All fields required",
        success: false,
        error: true,
      });
      return;
    }

    const token = jwt.sign({ name: name }, process.env.JWT_TOKEN, {
      expiresIn: "1m",
    });

    res.status(200).json({
      message: "Successfully Loged in",
      token: token,
      success: true,
      error: false,
    });
  } catch (error) {
    console.log("Error", error.message);
    res.status(500).json({
      message: "Internal server error",
      success: false,
      error: true,
    });
  }
});

// Start Server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
