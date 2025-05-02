package com.nmap.nMapScanner.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nmap.nMapScanner.model.ScanSession;
import com.nmap.nMapScanner.model.ScanSessionSummary;
import com.nmap.nMapScanner.model.ScannedIP;
import com.nmap.nMapScanner.model.ScannedIpDto;
import com.nmap.nMapScanner.repository.ScanSessionRepository;
import com.nmap.nMapScanner.repository.ScannedIPRepository;
import com.nmap.nMapScanner.service.IScannerService;
import com.nmap.nMapScanner.service.ScanHistoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.*;
import java.util.stream.Collectors;

@Controller
@RequestMapping(value = "/dashboard")
public class DashboardController {

    @Autowired
    private ScanHistoryService scanHistoryService;

    @Autowired
    private ScanSessionRepository scanSessionRepository;

    @GetMapping("/profiles")
    public String viewScanHistory(Model model) {
        Map<String, List<ScanSession>> groupedHistory = scanHistoryService.getScanHistoryGroupedByProfile();
        groupedHistory.values().forEach(Collections::reverse);

        model.addAttribute("scanHistory", groupedHistory);
        return "scanHistory";
    }


    @GetMapping("/profile/{name}")
    public String viewProfileDetails(@PathVariable String name, Model model) {
        // Get all scan sessions for the selected profile
        List<ScanSession> sessions = scanHistoryService.getScansForProfile(name);
        if (sessions.isEmpty()) {
            throw new RuntimeException("No sessions found for profile: " + name);
        }

        // Get latest scan session
        ScanSession session = sessions.get(sessions.size() - 1);

        // Get IP counts
        int ipsWithData = scanSessionRepository.countIpsWithData(session.getId());
        int ipsWithoutData = scanSessionRepository.countIpsWithoutData(session.getId());

        // 4. Parse JSON and extract UP IPs with data using  Jackson
        String json = session.getJsonResult();
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = null;

        try {
            jsonNode = objectMapper.readTree(json);
        } catch (Exception e) {
            throw new RuntimeException("Error parsing JSON", e);
        }

        List<String> validIps = new ArrayList<>();

        // Iterate over the JSON keys and check for "host down" status
        JsonNode finalJsonNode = jsonNode;
        jsonNode.fieldNames().forEachRemaining(key -> {
            if (!key.contains("host down")) {
                JsonNode data = finalJsonNode.get(key);
                if (data.isArray() && data.size() > 0) {
                    validIps.add(key);
                }
            }
        });

        // Map IPs to DTOs with random vulnerability levels
        List<ScannedIpDto> ipDtos = validIps.stream()
                .map(ip -> new ScannedIpDto(
                        ip,
                        (int) (Math.random() * 5),
                        (int) (Math.random() * 3),
                        (int) (Math.random() * 2)
                ))
                .toList();

        // Prepare scan summaries for this profile
        List<ScanSessionSummary> summaries = sessions.stream()
                .sorted(Comparator.comparing(ScanSession::getScanTime).reversed())
                .map(s -> new ScanSessionSummary(
                        s.getTarget(),
                        s.getScanType(),
                        s.getScanTime(),
                        s.getOpenPorts(),
                        s.getClosedPorts(),
                        s.getFilteredPorts()
                ))
                .toList();

        // Add all data to model
        model.addAttribute("profileName", name);
        model.addAttribute("scanSummaries", summaries);
        model.addAttribute("upCount", ipsWithData);
        model.addAttribute("downCount", ipsWithoutData);
        model.addAttribute("upIpAddress", ipDtos); // for progress bars

        return "profile_details";
    }


}
