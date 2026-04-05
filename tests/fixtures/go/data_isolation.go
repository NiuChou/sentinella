package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// --- D1: DB write detection ---

func CreateProject(ctx context.Context, pool *pgxpool.Pool, name string, userID string) error {
	// Should be detected as DbWriteRef (INSERT INTO projects)
	_, err := pool.Exec(ctx, "INSERT INTO projects (name, user_id) VALUES ($1, $2)", name, userID)
	return err
}

func UpdateTask(ctx context.Context, pool *pgxpool.Pool, taskID string, status string) error {
	// Should be detected as DbWriteRef (UPDATE tasks)
	_, err := pool.Exec(ctx, "UPDATE tasks SET status = $1 WHERE id = $2", status, taskID)
	return err
}

func DeleteAsset(ctx context.Context, pool *pgxpool.Pool, assetID string) error {
	// Should be detected as DbWriteRef (DELETE FROM assets)
	_, err := pool.Exec(ctx, "DELETE FROM assets WHERE id = $1", assetID)
	return err
}

// --- D2: RLS activation ---

func WithRLS(ctx context.Context, pool *pgxpool.Pool, userID string) error {
	// Should be detected as RlsContextRef
	_, err := pool.Exec(ctx, fmt.Sprintf("SET LOCAL app.current_user_id = '%s'", userID))
	return err
}

// --- D4: Missing ownership filter ---

func GetTaskByID(ctx context.Context, pool *pgxpool.Pool, taskID string) error {
	// SELECT without user_id filter — D5 should flag
	row := pool.QueryRow(ctx, "SELECT * FROM tasks WHERE id = $1", taskID)
	_ = row
	return nil
}

// --- D6: Redis cache-only ---

func CacheSessionState(ctx context.Context, rdb *redis.Client, sessionID string, data string) {
	// Redis SET with TTL, no DB write — D6 should flag
	rdb.Set(ctx, fmt.Sprintf("session:state:%s", sessionID), data, 86400)
}

func GetSessionState(ctx context.Context, rdb *redis.Client, sessionID string) string {
	// Redis GET — should be detected as RedisOp::Read
	val, _ := rdb.Get(ctx, fmt.Sprintf("session:state:%s", sessionID)).Result()
	return val
}

// --- D7: Hardcoded credentials ---

type Config struct {
	MinioAccessKey   string
	MinioSecretKey   string
	FederationSecret string
}

var defaultConfig = Config{
	MinioAccessKey:   "minioadmin",
	MinioSecretKey:   "minioadmin",
	FederationSecret: "federation_secret",
}

const InternalAPIKey = "dev-internal-key"
