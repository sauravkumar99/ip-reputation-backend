package com.security.ipanalyzer.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.security.ipanalyzer.model.IPResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Optional;

@Service
public class VirusTotalService {
 
 @Value("${api.virustotal.key}")
 private String apiKey;
 
 private static final String VT_URL =
         "https://www.virustotal.com/api/v3/ip_addresses/";
 
 private final RestTemplate restTemplate = new RestTemplate();
 
 public Optional<IPResult> checkIP(String ip) {
  
  try {
   System.out.println("🔍 VirusTotal checking IP: " + ip);
   
   HttpHeaders headers = new HttpHeaders();
   headers.set("x-apikey", apiKey);
   headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
   
   HttpEntity<Void> entity = new HttpEntity<>(headers);
   
   ResponseEntity<JsonNode> response = restTemplate.exchange(
           VT_URL + ip,
           HttpMethod.GET,
           entity,
           JsonNode.class
   );
   
   if (!response.getStatusCode().is2xxSuccessful()) {
    return Optional.empty();
   }
   
   JsonNode root = response.getBody();
   if (root == null) return Optional.empty();
   
   JsonNode attributes = root.path("data").path("attributes");
   if (attributes.isMissingNode()) return Optional.empty();
   
   JsonNode stats = attributes.path("last_analysis_stats");
   if (stats.isMissingNode()) return Optional.empty();
   
   int malicious = stats.path("malicious").asInt(0);
   int suspicious = stats.path("suspicious").asInt(0);
   
   IPResult result = new IPResult();
   result.setIp(ip);
   result.setSource("VirusTotal");
   result.setScore(malicious + suspicious);
   result.setMalicious(malicious > 0);
   result.setCountry(attributes.path("country").asText(null));
   
   // ASN is numeric in VirusTotal
   if (attributes.has("asn")) {
    result.setAsn(String.valueOf(attributes.path("asn").asInt()));
   }
   
   System.out.println("✅ VirusTotal OK: " + ip +
           " score=" + result.getScore());
   
   return Optional.of(result);
   
  } catch (HttpClientErrorException.TooManyRequests e) {
   System.err.println("❌ VirusTotal rate limit hit");
   return Optional.empty();
  } catch (HttpClientErrorException.Unauthorized e) {
   System.err.println("❌ VirusTotal API key invalid");
   return Optional.empty();
  } catch (Exception e) {
   e.printStackTrace();
   return Optional.empty();
  }
 }
}
