package com.security.ipanalyzer.service;

import com.security.ipanalyzer.model.IPResult;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class RedisCacheService {

    private final RedisTemplate<String, IPResult> redisTemplate;

    // 6 hour TTL — same as original
    private static final Duration TTL        = Duration.ofHours(6);
    // Namespace prefix so keys don't collide with anything else in Redis
    private static final String   KEY_PREFIX = "ip:";

    public RedisCacheService(RedisTemplate<String, IPResult> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public IPResult get(String ip) {
        try {
            IPResult result = redisTemplate.opsForValue().get(KEY_PREFIX + ip);
            // Validate the object came back properly — if ip field is null, treat as miss
            if (result != null && result.getIp() != null) {
                System.out.println("[Cache] HIT: " + ip);
                return result;
            }
            System.out.println("[Cache] MISS: " + ip);
            return null;
        } catch (Exception e) {
            System.err.println("[Cache] GET error for " + ip + ": " + e.getMessage());
            return null;
        }
    }

    public void put(String ip, IPResult result) {
        if (result == null || result.getIp() == null) return;
        try {
            redisTemplate.opsForValue().set(KEY_PREFIX + ip, result, TTL);
            System.out.println("[Cache] STORED: " + ip);
        } catch (Exception e) {
            System.err.println("[Cache] PUT error for " + ip + ": " + e.getMessage());
        }
    }
}
