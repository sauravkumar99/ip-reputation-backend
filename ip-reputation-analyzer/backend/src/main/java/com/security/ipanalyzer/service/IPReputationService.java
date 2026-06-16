package com.security.ipanalyzer.service;

import com.security.ipanalyzer.model.IPResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class IPReputationService {

    @Autowired private VirusTotalService virusTotalService;
    @Autowired private AbuseIPDBService  abuseIPDBService;
    @Autowired private GreyNoiseService  greyNoiseService;
    @Autowired private RedisCacheService cache;

    // ── IP Validation ────────────────────────────────────────────────────────
    private static final Pattern IPV4 = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$");
    private static final Pattern IPV6 = Pattern.compile(
            "^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$");

    private static boolean isValidIP(String ip) {
        return ip != null && (IPV4.matcher(ip).matches() || IPV6.matcher(ip).matches());
    }

    // ── Private IP ranges ────────────────────────────────────────────────────
    private static boolean isPrivateIP(String ip) {
        if (ip == null) return true;
        if (ip.equals("::1")) return true;
        String[] p = ip.split("\\.");
        if (p.length != 4) return false;
        try {
            int a = Integer.parseInt(p[0]);
            int b = Integer.parseInt(p[1]);
            if (a == 10) return true;
            if (a == 172 && b >= 16 && b <= 31) return true;
            if (a == 192 && b == 168) return true;
            if (a == 127) return true;
            if (a == 169 && b == 254) return true;
            if (a == 0)  return true;
        } catch (NumberFormatException e) { return true; }
        return false;
    }

    // ── Thread pool ──────────────────────────────────────────────────────────
    // Large pool so VT + AbuseIPDB for ALL IPs can run truly in parallel
    private final ExecutorService executor = Executors.newCachedThreadPool();

    // ── Main entry point ─────────────────────────────────────────────────────
    public List<IPResult> analyze(List<String> ips) {
        if (ips == null || ips.isEmpty()) return Collections.emptyList();

        List<String> unique = ips.stream()
                .map(ip -> ip == null ? "" : ip.trim())
                .filter(ip -> !ip.isEmpty())
                .filter(ip -> {
                    if (!isValidIP(ip)) {
                        System.err.println("[Validation] Skipping: " + ip);
                        return false;
                    }
                    return true;
                })
                .distinct()
                .collect(Collectors.toList());

        if (unique.isEmpty()) return Collections.emptyList();

        // Launch all IPs in parallel — no timeout so slow APIs are still waited on
        List<CompletableFuture<IPResult>> futures = unique.stream()
                .map(ip -> CompletableFuture.supplyAsync(() -> analyzeSingleIP(ip), executor))
                .collect(Collectors.toList());

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        return futures.stream()
                .map(f -> { try { return f.get(); } catch (Exception e) { return null; } })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    // ── Per-IP logic ─────────────────────────────────────────────────────────
    private IPResult analyzeSingleIP(String ip) {

        // 1. Private IP — return instantly, no API call
        if (isPrivateIP(ip)) {
            System.out.println("[Private] " + ip);
            return buildResult(ip, "Private/Reserved", 0, false, "Private", "N/A");
        }

        // 2. Cache check — return immediately if found, skip ALL API calls
        try {
            IPResult cached = cache.get(ip);
            if (cached != null) {
                // Mark as cached so UI can show cache hit count
                if (!cached.getSource().contains("[Cache]")) {
                    cached.setSource(cached.getSource() + " [Cache]");
                }
                return cached;
            }
        } catch (Exception e) {
            System.err.println("[Cache] Error reading " + ip + ": " + e.getMessage());
        }

        // 3. Race VT vs AbuseIPDB — whoever responds first wins.
        //    We do NOT wait for both. First result = done. Second is cancelled.
        //    This is the key change: you said "if served from any one, it's fine".
        CompletableFuture<Optional<IPResult>> vtFuture =
                CompletableFuture.supplyAsync(() -> {
                    try { return virusTotalService.checkIP(ip); }
                    catch (Exception e) { return Optional.empty(); }
                }, executor);

        CompletableFuture<Optional<IPResult>> abuseFuture =
                CompletableFuture.supplyAsync(() -> {
                    try { return abuseIPDBService.checkIP(ip); }
                    catch (Exception e) { return Optional.empty(); }
                }, executor);

        // anyOf returns as soon as EITHER completes
        // We check the result — if it has data, use it immediately
        // If first responder returns empty (rate limit etc), wait for the other
        IPResult result = null;

        try {
            // Wait for first non-empty result using a simple polling approach
            // Check every 500ms if any future has a real result
            long startTime = System.currentTimeMillis();
            long maxWait   = 60_000; // 60s max total wait

            while (System.currentTimeMillis() - startTime < maxWait) {
                // Check VT
                if (vtFuture.isDone()) {
                    Optional<IPResult> vt = vtFuture.get();
                    if (vt.isPresent()) {
                        result = vt.get();
                        abuseFuture.cancel(true); // cancel the other, we have what we need
                        System.out.println("[VT won race] " + ip);
                        break;
                    }
                }
                // Check AbuseIPDB
                if (abuseFuture.isDone()) {
                    Optional<IPResult> abuse = abuseFuture.get();
                    if (abuse.isPresent()) {
                        result = abuse.get();
                        vtFuture.cancel(true); // cancel the other
                        System.out.println("[AbuseIPDB won race] " + ip);
                        break;
                    }
                }
                // Both done but both empty — no point waiting
                if (vtFuture.isDone() && abuseFuture.isDone()) {
                    System.out.println("[Both empty] " + ip + " — trying GreyNoise");
                    break;
                }
                Thread.sleep(500); // poll every 500ms
            }
        } catch (Exception e) {
            System.err.println("[Race] " + ip + ": " + e.getMessage());
        }

        // 4. If both were empty, try GreyNoise as last resort
        if (result == null) {
            try {
                Optional<IPResult> grey = greyNoiseService.checkIP(ip);
                if (grey.isPresent()) result = grey.get();
            } catch (Exception e) {
                System.err.println("[GreyNoise] " + ip + ": " + e.getMessage());
            }
        }

        // 5. Still nothing — return No Data
        if (result == null) {
            return buildResult(ip, "No Data", 0, false, null, null);
        }

        // 6. Store in cache so next time this IP is instant
        try {
            cache.put(ip, result);
        } catch (Exception e) {
            System.err.println("[Cache] PUT failed for " + ip);
        }

        return result;
    }

    private IPResult buildResult(String ip, String source, int score,
                                 boolean malicious, String country, String asn) {
        IPResult r = new IPResult();
        r.setIp(ip);
        r.setSource(source);
        r.setScore(score);
        r.setMalicious(malicious);
        r.setCountry(country);
        r.setAsn(asn);
        return r;
    }
}
