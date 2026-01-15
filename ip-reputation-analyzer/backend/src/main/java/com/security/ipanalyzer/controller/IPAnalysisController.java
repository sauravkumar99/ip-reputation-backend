package com.security.ipanalyzer.controller;

import com.security.ipanalyzer.model.IPResult;
import com.security.ipanalyzer.service.IPReputationService;
import org.springframework.web.bind.annotation.*;

import java.util.List;
@CrossOrigin
@RestController
public class IPAnalysisController {
 
 private final IPReputationService service;
 
 public IPAnalysisController(IPReputationService service) {
  this.service = service;
 }
 
 // ✅ HARD-BIND ENDPOINT (NO CLASS PREFIX)
 @PostMapping("/api/analyze")
 public List<IPResult> analyze(@RequestBody List<String> ips) {
  return service.analyze(ips);
 }
}
