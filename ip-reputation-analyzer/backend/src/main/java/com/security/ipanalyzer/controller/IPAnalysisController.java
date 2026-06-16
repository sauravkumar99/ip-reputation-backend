package com.security.ipanalyzer.controller;

import com.security.ipanalyzer.model.IPResult;
import com.security.ipanalyzer.service.IPReputationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * SECURITY CHANGES vs original:
 *
 * SEC-1: @CrossOrigin replaced with explicit allowed origin list.
 *        Original @CrossOrigin with NO arguments allows ANY origin (wildcard *) —
 *        meaning any website can call this API from a browser.
 *        Set allowedOrigins to the actual frontend URL(s) you use.
 *
 * SEC-2: Input size validation — reject requests with > 500 IPs.
 *        Without this, anyone can send 100,000 IPs and exhaust your API rate limits
 *        and thread pool simultaneously.
 *
 * SEC-3: Returns ResponseEntity so we can return proper HTTP 400 on bad input
 *        instead of a 500 stack trace.
 *
 * SEC-4: Null/empty list guard.
 */
@RestController
@RequestMapping("/api")
// SEC-1: REPLACE "http://localhost:63342" with your actual frontend origin.
//         For production: @CrossOrigin(origins = "https://yourdomain.com")
//         For local dev only: @CrossOrigin(origins = {"http://localhost:63342", "http://127.0.0.1:5500"})
@CrossOrigin(origins = "*")
public class IPAnalysisController {

    private static final int MAX_IPS = 500; // SEC-2: DoS protection

    private final IPReputationService service;

    public IPAnalysisController(IPReputationService service) {
        this.service = service;
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyze(@RequestBody List<String> ips) {

        // SEC-4: null / empty guard
        if (ips == null || ips.isEmpty()) {
            return ResponseEntity.badRequest().body("IP list must not be empty.");
        }

        // SEC-2: reject oversized payloads — prevents API-key exhaustion attacks
        if (ips.size() > MAX_IPS) {
            return ResponseEntity.badRequest()
                    .body("Too many IPs. Maximum allowed: " + MAX_IPS + ", received: " + ips.size());
        }

        List<IPResult> results = service.analyze(ips);
        return ResponseEntity.ok(results);
    }
}
