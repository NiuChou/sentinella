import { Router } from "express";
import { Controller, Get, Post, Delete } from "@nestjs/common";

// Express-style routes
const router = Router();

router.get("/api/users", (req, res) => {
  res.json({ users: [] });
});

router.post("/api/users", (req, res) => {
  res.status(201).json(req.body);
});

router.put("/api/users/:id", (req, res) => {
  res.json({ updated: true });
});

router.delete("/api/users/:id", (req, res) => {
  res.status(204).send();
});

// NestJS-style routes
@Controller("orders")
class OrderController {
  @Get("list")
  findAll() {
    return [];
  }

  @Post("create")
  create() {
    return {};
  }

  @Delete(":id")
  remove() {
    return {};
  }
}

export default router;
