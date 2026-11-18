import type { NextFunction, Request, Response } from 'express';

interface Bucket {
  tokens: number;
  lastRefillMs: number;
}

export class TokenBucketRateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly capacity: number;
  private readonly refillPerSecond: number;
  private readonly cleanupTimer: NodeJS.Timeout;

  constructor(options: { capacity?: number; refillPerSecond?: number } = {}) {
    this.capacity = options.capacity ?? 200;
    this.refillPerSecond = options.refillPerSecond ?? 100;
    this.cleanupTimer = setInterval(() => this.prune(), 60_000);
    this.cleanupTimer.unref();
  }

  consume(key: string, cost = 1): { allowed: boolean; remaining: number } {
    const now = Date.now();
    const existing = this.buckets.get(key);
    if (!existing) {
      const remaining = Math.max(0, this.capacity - cost);
      this.buckets.set(key, { tokens: remaining, lastRefillMs: now });
      return { allowed: true, remaining };
    }

    const elapsedSec = Math.max(0, (now - existing.lastRefillMs) / 1000);
    const replenished = Math.min(
      this.capacity,
      existing.tokens + elapsedSec * this.refillPerSecond,
    );

    if (replenished < cost) {
      existing.tokens = replenished;
      existing.lastRefillMs = now;
      return { allowed: false, remaining: 0 };
    }

    existing.tokens = replenished - cost;
    existing.lastRefillMs = now;
    return { allowed: true, remaining: Math.floor(existing.tokens) };
  }

  middleware() {
    return (req: Request, res: Response, next: NextFunction): void => {
      const key = req.ip || req.socket.remoteAddress || 'unknown';
      const result = this.consume(key);
      res.setHeader('X-RateLimit-Remaining', String(result.remaining));
      if (!result.allowed) {
        res.status(429).json({ error: 'RATE_LIMIT_EXCEEDED' });
        return;
      }
      next();
    };
  }

  private prune(): void {
    const cutoff = Date.now() - 5 * 60_000;
    for (const [key, bucket] of this.buckets.entries()) {
      if (bucket.lastRefillMs < cutoff) {
        this.buckets.delete(key);
      }
    }
  }

  stop(): void {
    clearInterval(this.cleanupTimer);
    this.buckets.clear();
  }
}
