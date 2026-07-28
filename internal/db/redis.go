package db

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/user/waf/internal/config"
)

type Redis struct {
	Client *redis.Client
}

// NewRedis creates a Redis client. If cfg.Sentinel.Enabled is true, uses
// Sentinel failover for HA. Otherwise connects to cfg.URL directly.
func NewRedis(ctx context.Context, cfg config.RedisConfig) (*Redis, error) {
	var client *redis.Client
	if cfg.Sentinel.Enabled {
		opts := &redis.FailoverOptions{
			MasterName:    cfg.Sentinel.MasterName,
			SentinelAddrs: cfg.Sentinel.Addrs,
			Password:      cfg.Sentinel.Password,
			DB:            0,
		}
		client = redis.NewFailoverClient(opts)
	} else {
		opts, err := redis.ParseURL(cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("parse redis url: %w", err)
		}
		client = redis.NewClient(opts)
	}

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return &Redis{Client: client}, nil
}

func (r *Redis) Close() error {
	return r.Client.Close()
}

func (r *Redis) Ping(ctx context.Context) error {
	return r.Client.Ping(ctx).Err()
}
