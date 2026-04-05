// Direct access
const dbUrl = process.env.DATABASE_URL;

// With fallback (nullish coalescing)
const port = process.env.PORT ?? "3000";

// With fallback (logical OR)
const host = process.env.HOST || "localhost";

// No fallback
const apiKey = process.env.API_KEY;

// Destructured
const { NODE_ENV, SECRET_KEY } = process.env;
