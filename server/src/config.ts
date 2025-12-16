const jwtSecret = process.env.JWT_SECRET;

if (!jwtSecret) {
  if (process.env.NODE_ENV === "production") {
    throw new Error("JWT_SECRET is not defined");
  }
}

export const JWT_SECRET: string = jwtSecret ?? "dev-secret";
