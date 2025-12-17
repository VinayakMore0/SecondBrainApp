import mongoose, { model } from "mongoose";

const Schema = mongoose.Schema;
const ObjectId = Schema.Types.ObjectId;

const contentTypes = ["image", "video", "article", "audio"];

const userSchema = new Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const tagSchema = new Schema({
  title: { type: String, required: true, unique: true },
});

const contentSchema = new Schema({
  link: { type: String, required: true },
  type: { type: String, required: true, enum: contentTypes },
  title: { type: String, required: true },
  tags: [{ type: ObjectId, ref: "Tag" }],
  userId: { type: ObjectId, ref: "User", required: true },
});

const linkSchema = new Schema({
  hash: { type: String, required: true },
  userId: { type: ObjectId, ref: "User", required: true },
});

const User = model("User", userSchema);
const Tag = model("Tag", tagSchema);
const Content = model("Content", contentSchema);
const Link = model("Link", linkSchema);

export { User, Tag, Content, Link };
