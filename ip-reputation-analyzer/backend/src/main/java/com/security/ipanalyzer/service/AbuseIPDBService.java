package com.security.ipanalyzer.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.security.ipanalyzer.model.IPResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Optional;

@Service
public class AbuseIPDBService {

    @Value("${api.abuseipdb.key}")
    private String apiKey;

    private static final String ABUSE_URL =
            "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=";

    // Increased timeouts
    private final RestTemplate restTemplate;

    public AbuseIPDBService() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(5_000);   // 5s to connect
        factory.setReadTimeout(20_000);     // 20s to read
        this.restTemplate = new RestTemplate(factory);
    }

    public Optional<IPResult> checkIP(String ip) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Key", apiKey);
            headers.set("Accept", "application/json");

            ResponseEntity<JsonNode> response = restTemplate.exchange(
                    ABUSE_URL + ip, HttpMethod.GET,
                    new HttpEntity<>(headers), JsonNode.class);

            JsonNode root = response.getBody();
            if (root == null) return Optional.empty();

            JsonNode data = root.path("data");
            if (data.isMissingNode()) return Optional.empty();

            int abuseScore = data.path("abuseConfidenceScore").asInt(0);

            IPResult result = new IPResult();
            result.setIp(ip);
            result.setSource("AbuseIPDB");
            result.setScore(abuseScore);
            result.setMalicious(abuseScore > 0);
            result.setCountry(data.path("countryCode").asText("N/A"));
            result.setAsn(data.path("domain").asText("N/A")); // domain as fallback for ASN

            return Optional.of(result);

        } catch (HttpClientErrorException.TooManyRequests e) {
            System.err.println("[AbuseIPDB] Rate limit hit for " + ip + " — free tier: 1000 checks/day");
            return Optional.empty();
        } catch (HttpClientErrorException.Unauthorized e) {
            System.err.println("[AbuseIPDB] Invalid API key — check application.yml");
            return Optional.empty();
        } catch (Exception e) {
            System.err.println("[AbuseIPDB] " + ip + ": " + e.getMessage());
            return Optional.empty();
        }
    }
}
