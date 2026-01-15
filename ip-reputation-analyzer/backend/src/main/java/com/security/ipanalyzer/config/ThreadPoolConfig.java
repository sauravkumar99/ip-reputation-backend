package com.security.ipanalyzer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Configuration
public class ThreadPoolConfig {
	
	@Bean(name = "ipExecutor")
	public ExecutorService ipExecutor() {
		int cores = Runtime.getRuntime().availableProcessors();
		return Executors.newFixedThreadPool(cores * 2);
	}
}
