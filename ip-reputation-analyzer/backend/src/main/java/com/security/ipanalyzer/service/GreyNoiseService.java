package com.security.ipanalyzer.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.security.ipanalyzer.model.IPResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Optional;

@Service
public class GreyNoiseService {
 
 @Value("${api.greynoise.key}")
 private String apiKey;
 
 private static final String GREY_URL =
         "https://api.greynoise.io/v3/community/";
 
 private final RestTemplate restTemplate = new RestTemplate();
 
 public Optional<IPResult> checkIP(String ip) {
  
  try {
   HttpHeaders headers = new HttpHeaders();
   headers.set("key", apiKey);
   headers.setAccept(List.of(MediaType.APPLICATION_JSON));
   
   HttpEntity<Void> entity = new HttpEntity<>(headers);
   
   ResponseEntity<JsonNode> response = restTemplate.exchange(
           GREY_URL + ip,
           HttpMethod.GET,
           entity,
           JsonNode.class
   );
   
   JsonNode root = response.getBody();
   if (root == null) return Optional.empty();
   
   boolean noise = root.path("noise").asBoolean(false);
   
   IPResult result = new IPResult();
   result.setIp(ip);
   result.setSource("GreyNoise");
   result.setMalicious(noise);
   result.setScore(noise ? 50 : 0);
   result.setCountry("N/A");
   
   return Optional.of(result);
   
  } catch (Exception e) {
   return Optional.empty();
  }
 }
}
