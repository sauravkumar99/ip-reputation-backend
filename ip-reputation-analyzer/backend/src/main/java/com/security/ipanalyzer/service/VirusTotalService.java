package com.security.ipanalyzer.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.security.ipanalyzer.model.IPResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Optional;

@Service
public class VirusTotalService {

    @Value("${api.virustotal.key}")
    private String apiKey;

    private static final String VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/";

    // Increased timeouts — VT free tier can be slow (5–15s response time)
    private final RestTemplate restTemplate;

    public VirusTotalService() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(5_000);   // 5s to connect
        factory.setReadTimeout(20_000);     // 20s to read — VT free tier is slow
        this.restTemplate = new RestTemplate(factory);
    }

    public Optional<IPResult> checkIP(String ip) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("x-apikey", apiKey);
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

            ResponseEntity<JsonNode> response = restTemplate.exchange(
                    VT_URL + ip, HttpMethod.GET,
                    new HttpEntity<>(headers), JsonNode.class);

            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null)
                return Optional.empty();

            JsonNode attrs = response.getBody().path("data").path("attributes");
            if (attrs.isMissingNode()) return Optional.empty();

            JsonNode stats = attrs.path("last_analysis_stats");
            int malicious  = stats.path("malicious").asInt(0);
            int suspicious = stats.path("suspicious").asInt(0);

            IPResult result = new IPResult();
            result.setIp(ip);
            result.setSource("VirusTotal");
            result.setScore(Math.min(malicious + suspicious, 100));
            result.setMalicious(malicious > 0);
            result.setCountry(attrs.path("country").asText(null));
            if (attrs.has("asn"))
                result.setAsn("AS" + attrs.path("asn").asInt());

            return Optional.of(result);

        } catch (HttpClientErrorException.TooManyRequests e) {
            System.err.println("[VirusTotal] Rate limit hit for " + ip + " — free tier: 4 requests/min");
            return Optional.empty();
        } catch (HttpClientErrorException.Unauthorized e) {
            System.err.println("[VirusTotal] Invalid API key — check application.yml");
            return Optional.empty();
        } catch (Exception e) {
            System.err.println("[VirusTotal] " + ip + ": " + e.getMessage());
            return Optional.empty();
        }
    }
}
