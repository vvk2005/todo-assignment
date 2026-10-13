
import "dotenv/config";
import express from "express";
import { PrismaClient } from "@prisma/client";
import { z } from "zod";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
const prisma = new PrismaClient();

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET missing in .env");
}

const signupSchema = z.object({
  name: z.string().trim().min(2),
  email: z.string().trim().email().transform((v) => v.toLowerCase()),
  password: z.string().min(6).max(72),
});

const loginSchema = z.object({
  email: z.string().trim().email().transform((v) => v.toLowerCase()),
  password: z.string().min(1),
});

const todoSchema = z.object({
  title: z.string().trim().min(1).max(200),
});

type AuthRequest = express.Request & {
  userId?: number;
};

// JWT authentication middleware
function authenticateToken(
  req: AuthRequest,
  res: express.Response,
  next: express.NextFunction
) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ")
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ message: "Token required" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET!) as {
      userId: number;
    };

    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// Home route
app.get("/", (_req, res) => {
  res.json({ message: "Todo App Backend is running on port 3001" });
});

// Signup
app.post("/signup", async (req, res) => {
  try {
    const parsed = signupSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        message: "Invalid signup data",
        errors: parsed.error.issues,
      });
    }

    const { name, email, password } = parsed.data;

    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(409).json({
        message: "Email already registered. Please login.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { name, email, password: hashedPassword },
      select: { id: true, name: true, email: true },
    });

    const token = jwt.sign(
      { userId: user.id },
      JWT_SECRET!,
      { expiresIn: "1d" }
    );

    return res.status(201).json({
      message: "Signup successful",
      user,
      token,
    });
  } catch (error) {
    console.error("Signup error:", error);
    return res.status(500).json({ message: "Signup failed" });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const parsed = loginSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        message: "Invalid login data",
        errors: parsed.error.issues,
      });
    }

    const { email, password } = parsed.data;

    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatches) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }

    const token = jwt.sign(
      { userId: user.id },
      JWT_SECRET!,
      { expiresIn: "1d" }
    );

    return res.status(200).json({
      message: "Login successful",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
      token,
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ message: "Login failed" });
  }
});

// Create Todo
app.post("/todos", authenticateToken, async (req: AuthRequest, res) => {
  try {
    const parsed = todoSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        message: "Please provide a valid todo title",
        errors: parsed.error.issues,
      });
    }

    const todo = await prisma.todo.create({
      data: {
        title: parsed.data.title,
        userId: req.userId!,
      },
    });

    return res.status(201).json({
      message: "Todo created successfully",
      todo,
    });
  } catch (error) {
    console.error("Create todo error:", error);
    return res.status(500).json({ message: "Could not create todo" });
  }
});

// Fetch logged-in user's Todos
app.get("/todos", authenticateToken, async (req: AuthRequest, res) => {
  try {
    const todos = await prisma.todo.findMany({
      where: { userId: req.userId! },
      orderBy: { createdAt: "desc" },
    });

    return res.status(200).json({ todos });
  } catch (error) {
    console.error("Fetch todos error:", error);
    return res.status(500).json({ message: "Could not fetch todos" });
  }
});

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ message: "Route not found" });
});

const server = app.listen(3001, () => {
  console.log("TODO APP RUNNING ON PORT 3001");
  console.log("POST /signup | POST /login | POST /todos | GET /todos");
});

async function shutdown() {
  server.close();
  await prisma.$disconnect();
  process.exit(0);
}

process.on("SIGINT", () => {
  void shutdown();
});

process.on("SIGTERM", () => {
  void shutdown();
});


