package com.security.ipanalyzer.service;

import com.security.ipanalyzer.model.IPResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.*;
import java.util.stream.Collectors;

@Service
public class IPReputationService {
    
    @Autowired
    private VirusTotalService virusTotalService;
    
    @Autowired
    private AbuseIPDBService abuseIPDBService;
    
    @Autowired
    private GreyNoiseService greyNoiseService;
    
    @Autowired
    private RedisCacheService cache;
    
    // Controlled thread pool (prevents API flooding)
    private final ExecutorService executor =
            Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);
    
    public List<IPResult> analyze(List<String> ips) {
        return ips.parallelStream()
                .map(this::analyzeSingleIP)
                .collect(Collectors.toList());
    }
    
    private IPResult analyzeSingleIP(String ip) {
        
        if (ip == null) {
            return buildInvalidIP("null");
        }
        
        ip = ip.trim();
        
        if (!isValidIP(ip)) {
            return buildInvalidIP(ip);
        }
        
        final String ipFinal = ip; // ✅ FIX FOR LAMBDA
        
        // 1️⃣ REDIS CACHE
        IPResult cached = cache.get(ipFinal);
        if (cached != null && !"No Data".equals(cached.getSource())) {
            return cached;
        }
        
        try {
            // 2️⃣ CALL BOTH IN PARALLEL
            CompletableFuture<Optional<IPResult>> vtFuture =
                    CompletableFuture.supplyAsync(
                            () -> virusTotalService.checkIP(ipFinal),
                            executor
                    ).exceptionally(ex -> {
                        logRateLimit(ex);
                        return Optional.empty();
                    });
            
            CompletableFuture<Optional<IPResult>> abuseFuture =
                    CompletableFuture.supplyAsync(
                            () -> abuseIPDBService.checkIP(ipFinal),
                            executor
                    ).exceptionally(ex -> Optional.empty());
            
            CompletableFuture.allOf(vtFuture, abuseFuture).join();
            
            Optional<IPResult> vt = vtFuture.get();
            Optional<IPResult> abuse = abuseFuture.get();
            
            // 3️⃣ MERGE RESULTS
            if (vt.isPresent() || abuse.isPresent()) {
                IPResult merged = merge(ipFinal, vt, abuse);
                cache.put(ipFinal, merged);
                return merged;
            }
            
            // 4️⃣ GREYNOISE LAST
            Optional<IPResult> grey = greyNoiseService.checkIP(ipFinal);
            if (grey.isPresent()) {
                cache.put(ipFinal, grey.get());
                return grey.get();
            }
            
        } catch (Exception ignored) {
        }
        
        return buildNoData(ipFinal);
    }
    
    private IPResult merge(String ip,
                           Optional<IPResult> vt,
                           Optional<IPResult> abuse) {
        
        IPResult r = new IPResult();
        r.setIp(ip);
        
        int score = 0;
        boolean malicious = false;
        String source = "";
        
        if (vt.isPresent()) {
            score = vt.get().getScore();
            malicious = vt.get().isMalicious();
            r.setCountry(vt.get().getCountry());
            r.setAsn(vt.get().getAsn());
            source = "VirusTotal";
        }
        
        if (abuse.isPresent()) {
            score = Math.max(score, abuse.get().getScore()); // ✅ NO ADDING
            malicious |= abuse.get().isMalicious();
            source = source.isEmpty() ? "AbuseIPDB" : "VirusTotal + AbuseIPDB";
        }
        
        r.setScore(score);
        r.setMalicious(malicious);
        r.setSource(source);
        
        return r;
    }
    
    private IPResult buildNoData(String ip) {
        IPResult r = new IPResult();
        r.setIp(ip);
        r.setSource("No Data");
        r.setScore(0);
        r.setMalicious(false);
        return r;
    }
    
    private IPResult buildInvalidIP(String ip) {
        IPResult r = new IPResult();
        r.setIp(ip);
        r.setSource("Invalid IP");
        r.setScore(0);
        r.setMalicious(false);
        return r;
    }
    
    private void logRateLimit(Throwable ex) {
        if (ex.getMessage() != null &&
                ex.getMessage().toLowerCase().contains("rate")) {
            System.err.println("❌ VirusTotal rate limit exceeded");
        }
    }
    
    private boolean isValidIP(String ip) {
        String ipv4 =
                "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}" +
                        "(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$";
        
        String ipv6 = "^[0-9a-fA-F:]+$";
        
        return ip.matches(ipv4) || ip.matches(ipv6);
    }
}
