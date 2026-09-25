const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret";
const GROQ_API_KEY = process.env.GROQ_API_KEY;

// =========================
// CORS
// =========================

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  res.header(
    "Access-Control-Allow-Methods",
    "GET, POST, OPTIONS"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }

  next();
});

app.use(express.json());

// =========================
// TEST DATABASE
// =========================

const users = [];

// =========================
// AI MODELS
// =========================

const MODELS = {
  ai1: "openai/gpt-oss-120b",
  ai2: "openai/gpt-oss-20b",
  ai3: "MODEL_3",
  ai4: "MODEL_4",
  ai5: "MODEL_5"
};

// =========================
// SIGN UP
// =========================

app.post("/api/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    const existingUser = users.find(
      user => user.email.toLowerCase() === email.toLowerCase()
    );

    if (existingUser) {
      return res.status(400).json({
        error: "An account with that email already exists."
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = {
      id: Date.now().toString(),
      email,
      passwordHash,
      subscribed: true
    };

    users.push(user);

    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email
      },
      JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    res.json({
      message: "Account created successfully.",
      token
    });

  } catch (error) {
    console.error("Signup error:", error);

    res.status(500).json({
      error: "Something went wrong."
    });
  }
});

// =========================
// LOGIN
// =========================

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    const user = users.find(
      user => user.email.toLowerCase() === email.toLowerCase()
    );

    if (!user) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const validPassword = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!validPassword) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email
      },
      JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    res.json({
      message: "Login successful.",
      token
    });

  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "Something went wrong."
    });
  }
});

// =========================
// AUTH MIDDLEWARE
// =========================

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();

  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired session."
    });
  }
}

// =========================
// CURRENT USER
// =========================

app.get("/api/me", authenticate, (req, res) => {
  const user = users.find(user => user.id === req.user.userId);

  if (!user) {
    return res.status(404).json({
      error: "User not found."
    });
  }

  res.json({
    email: user.email,
    subscribed: user.subscribed
  });
});

// =========================
// AI CHAT
// =========================

app.post("/api/chat", authenticate, async (req, res) => {
  try {
    const { model, message } = req.body;

    if (!model || !MODELS[model]) {
      return res.status(400).json({
        error: "Invalid AI model."
      });
    }

    if (!message || !message.trim()) {
      return res.status(400).json({
        error: "Message is required."
      });
    }

    if (!GROQ_API_KEY) {
      return res.status(500).json({
        error: "Groq API key is not configured."
      });
    }

    const response = await fetch(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${GROQ_API_KEY}`
        },
        body: JSON.stringify({
          model: MODELS[model],
          messages: [
            {
              role: "user",
              content: message
            }
          ]
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("Groq error:", data);

      return res.status(response.status).json({
        error:
          data?.error?.message ||
          "Groq request failed."
      });
    }

    const answer =
      data?.choices?.[0]?.message?.content;

    if (!answer) {
      return res.status(500).json({
        error: "The AI returned no answer."
      });
    }

    res.json({
      answer
    });

  } catch (error) {
    console.error("Chat error:", error);

    res.status(500).json({
      error: "Something went wrong while contacting the AI."
    });
  }
});

// =========================
// HEALTH CHECK
// =========================

app.get("/", (req, res) => {
  res.send("NexaAI backend is running 🚀");
});

// =========================
// START SERVER
// =========================

app.listen(PORT, () => {
  console.log(`NexaAI backend running on port ${PORT}`);
});