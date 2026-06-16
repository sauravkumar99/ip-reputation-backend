package com.security.ipanalyzer.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

// Required for Redis JSON serialization/deserialization to work correctly.
// Without this, Jackson can't reconstruct the object from Redis and cache always misses.
@JsonIgnoreProperties(ignoreUnknown = true)
public class IPResult {

 private String ip;
 private String country;
 private String asn;
 private int score;
 private boolean malicious;
 private String source;

 // Default constructor required by Jackson for deserialization
 public IPResult() {}

 public String getIp() { return ip; }
 public void setIp(String ip) { this.ip = ip; }

 public String getCountry() { return country; }
 public void setCountry(String country) { this.country = country; }

 public String getAsn() { return asn; }
 public void setAsn(String asn) { this.asn = asn; }

 public int getScore() { return score; }
 public void setScore(int score) { this.score = score; }

 public boolean isMalicious() { return malicious; }
 public void setMalicious(boolean malicious) { this.malicious = malicious; }

 public String getSource() { return source; }
 public void setSource(String source) { this.source = source; }
}
