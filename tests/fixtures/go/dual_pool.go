package main

// Fixture for D8 Dual-Pool Detection — Go patterns.

import (
	"context"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Restricted pool for user-facing code
var appPool, _ = pgxpool.New(context.Background(), os.Getenv("DATABASE_URL_APP"))

// Admin pool for workers
var adminPool, _ = pgxpool.New(context.Background(), os.Getenv("DATABASE_URL_ADMIN"))

// WRONG: Gin handler using admin pool — D8 should flag
func GetUserProfile(c *gin.Context) {
	row := adminPool.QueryRow(c, "SELECT * FROM users WHERE id = $1", c.Param("id"))
	_ = row
}

// CORRECT: Gin handler using restricted pool
func GetUserSessions(c *gin.Context) {
	rows, _ := appPool.Query(c, "SELECT * FROM sessions WHERE user_id = $1", c.GetString("user_id"))
	_ = rows
}

// OK: Background worker using admin pool
func CleanupExpiredSessions(ctx context.Context) {
	adminPool.Exec(ctx, "DELETE FROM sessions WHERE expires_at < NOW()")
}
