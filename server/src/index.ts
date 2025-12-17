import dotenv from "dotenv";
dotenv.config();

import express from "express";
import mongoose, { Types } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import z from "zod";
import cors from "cors";
import { Tag, Content, User } from "./db.js";
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
const contentSchema = z.object({
  link: z.string().url(),
  type: z.enum(["image", "video", "article", "audio"]),
  title: z.string().min(1),
  tags: z.array(z.string().min(1)).optional(),
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
      res.status(403).json({ message: "Incorrect credentials" });
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
  if (!req.userId) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const parsed = contentSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(411).json({
      message: "Invalid input",
      errors: parsed.error.issues,
    });
  }

  const { link, type, title, tags } = parsed.data;

  try {
    let tagIds: Types.ObjectId[] = [];

    if (tags && tags.length > 0) {
      const normalizedTags = tags.map((t: string) => t.trim().toLowerCase());

      const existingTags = await Tag.find({
        title: { $in: normalizedTags },
      });

      const tagMap = new Map<string, Types.ObjectId>(
        existingTags.map((tag) => [tag.title, tag._id])
      );

      const newTags = normalizedTags
        .filter((t) => !tagMap.has(t))
        .map((t) => ({ title: t }));

      if (newTags.length > 0) {
        const created = await Tag.insertMany(newTags, {
          ordered: false,
        });

        created.forEach((tag) => tagMap.set(tag.title, tag._id));
      }

      tagIds = normalizedTags.map((t) => tagMap.get(t)!);
    }

    await Content.create({
      link,
      type,
      title,
      tags: tagIds,
      userId: new Types.ObjectId(req.userId),
    });

    return res.status(200).json({
      message: "Content added",
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      message: "Server error",
    });
  }
});

app.get("/api/v1/content", middleware, async (req, res) => {
  const userId = req.userId;
  if (!userId) return res.status(401).json({ message: "Unauthorized" });

  const content = await Content.find({
    userId: new Types.ObjectId(userId),
  }).populate("userId", "username");

  res.json({
    content,
  });
});

app.delete("/api/v1/content", middleware, async (req, res) => {
  const contentId = req.body.contentId;
  if (!contentId)
    return res.status(400).json({ message: "contentId required" });
  if (!req.userId) return res.status(401).json({ message: "Unauthorized" });

  await Content.deleteMany({
    _id: new Types.ObjectId(contentId),
    userId: new Types.ObjectId(req.userId),
  });

  res.json({ ok: true });
});

// app.post("/api/v1/brain/share", middleware, async (req, res) => {});

// app.get("/api/v1/brain/:shareLink", async (req, res) => {});

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

  app.listen(3000, () =>
    console.log("Listening on port http://localhost:3000/")
  );
}

main();
