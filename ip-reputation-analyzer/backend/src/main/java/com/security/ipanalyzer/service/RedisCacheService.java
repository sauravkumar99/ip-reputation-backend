package com.security.ipanalyzer.service;

import com.security.ipanalyzer.model.IPResult;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class RedisCacheService {
	
	private final RedisTemplate<String, IPResult> redisTemplate;
	private static final Duration TTL = Duration.ofHours(6);
	
	public RedisCacheService(RedisTemplate<String, IPResult> redisTemplate) {
		this.redisTemplate = redisTemplate;
	}
	
	public IPResult get(String ip) {
		try {
			return redisTemplate.opsForValue().get(ip);
		} catch (Exception e) {
			System.out.println("⚠ Redis unavailable (GET). Skipping cache.");
			return null;
		}
	}
	
	public void put(String ip, IPResult result) {
		try {
			redisTemplate.opsForValue().set(ip, result, TTL);
		} catch (Exception e) {
			System.out.println("⚠ Redis unavailable (PUT). Skipping cache write.");
		}
	}
}
