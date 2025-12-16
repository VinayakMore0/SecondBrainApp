import jwt, { type JwtPayload } from "jsonwebtoken";
import { JWT_SECRET } from "./config.js";
import type { NextFunction, Request, Response } from "express";

declare global {
  namespace Express {
    interface Request {
      userId?: string;
    }
  }
}

export const middleware = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(403).json({ message: "You are not signed in" });
  }

  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload | string;
    if (typeof decoded === "object" && decoded && "id" in decoded) {
      req.userId = String((decoded as any).id);
      return next();
    }

    return res.status(403).json({ message: "You are not signed in" });
  } catch (err) {
    return res.status(403).json({ message: "Invalid token" });
  }
};


