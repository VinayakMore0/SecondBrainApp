import dotenv from "dotenv";
dotenv.config();

import express from "express";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import z from "zod";
import cors from "cors";
import { Content, User } from "./db.js";
import { JWT_SECRET } from "./config.js";
import { middleware } from "./middleware.js";

const app = express();
app.use(express.json());
app.use(cors());

const signupSchema = z.object({
  username: z.string().min(3).max(10),
  password: z
    .string()
    .min(8)
    .max(20)
    .refine((val) => /[A-Z]/.test(val), {
      error: "Must include an uppercase letter",
    })
    .refine((val) => /[a-z]/.test(val), {
      error: "Must include a lowercase letter",
    })
    .refine((val) => /[^A-Za-z0-9]/.test(val), {
      error: "Must include a special character",
    })
    .refine((val) => /\d/.test(val), { error: "Must include a number" }),
});

app.post("/api/v1/signup", async (req, res) => {
  const parseData = signupSchema.safeParse(req.body);

  if (!parseData.success) {
    return res.status(411).json({
      message: "Invalid input",
      errors: parseData.error,
    });
  }

  try {
    const { username, password } = parseData.data;
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(403).json({
        message: "User already exists with this username",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      username,
      password: hashedPassword,
    });

    return res.status(200).json({
      message: "Signed up successfully",
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      message: "Server error",
    });
  }
});

app.post("/api/v1/signin", async (req, res) => {
  const parseData = signupSchema.safeParse(req.body);

  if (!parseData.success) {
    return res.status(411).json({
      message: "Invalid input",
      errors: parseData.error,
    });
  }

  try {
    const { username, password } = parseData.data;
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(403).json({
        message: "Invalid credentials",
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      res.status(403).json({
        message: "Incorrect credentials",
      });
    }

    const token = jwt.sign({ id: user._id.toString() }, JWT_SECRET, {
      expiresIn: "7d",
    });

    return res.status(200).json({
      message: "Signed in",
      token,
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      message: "Server error",
    });
  }
});

app.post("/api/v1/content", middleware, async (req, res) => {
    const {link, type, title, tags} = req.body;

    //@ts-ignore
    await Content.create({
        link, type, title, tags: [], userId: req.userId
    })

    res.json({
        message: "Content added"
    })
});

app.get("/api/v1/content", middleware, (req, res) => {});

app.delete("/api/v1/content", middleware, (req, res) => {});

app.post("/api/v1/brain/share", middleware, (req, res) => {});

app.get("/api/v1/brain/:shareLink", (req, res) => {});

async function main() {
  const mongoUrl = process.env.MONGO_URL;
  if (!mongoUrl) {
    throw new Error("MONGO_URL is not defined");
  }

  try {
    await mongoose.connect(mongoUrl);
  } catch (err) {
    console.error("Failed to connect to MongoDB:", err);
    process.exit(1);
  }

  app.listen(3000, () => console.log("Listening on port http://localhost:3000/"));
}

main();
