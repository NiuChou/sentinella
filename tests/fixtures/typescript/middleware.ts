import { Router } from "express";
import { authMiddleware } from "./auth";
import { rateLimiter } from "./rate-limit";
import { cors } from "./cors";

const router = Router();

router.use(authMiddleware);
router.use(rateLimiter);
router.use(cors);

router.get("/api/protected", (req, res) => {
  res.json({ ok: true });
});

export default router;
