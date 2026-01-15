package com.security.ipanalyzer.config;

import com.security.ipanalyzer.model.IPResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {
	
	@Value("${spring.data.redis.host}")
	private String host;
	
	@Value("${spring.data.redis.port}")
	private int port;
	
	@Value("${spring.data.redis.username}")
	private String username;
	
	@Value("${spring.data.redis.password}")
	private String password;
	
	@Bean
	public LettuceConnectionFactory redisConnectionFactory() {
		
		RedisStandaloneConfiguration config =
				new RedisStandaloneConfiguration(host, port);
		
		config.setUsername(username);   // Upstash → "default"
		config.setPassword(password);
		
		LettuceClientConfiguration clientConfig =
				LettuceClientConfiguration.builder()
						.useSsl()   // ✅ REQUIRED for Upstash
						.build();
		
		return new LettuceConnectionFactory(config, clientConfig);
	}
	
	// 🔥 IMPORTANT FIX: IPResult type
	@Bean
	public RedisTemplate<String, IPResult> redisTemplate() {
		
		RedisTemplate<String, IPResult> template = new RedisTemplate<>();
		template.setConnectionFactory(redisConnectionFactory());
		
		template.setKeySerializer(new StringRedisSerializer());
		template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
		
		template.setHashKeySerializer(new StringRedisSerializer());
		template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer());
		
		template.afterPropertiesSet();
		return template;
	}
}
