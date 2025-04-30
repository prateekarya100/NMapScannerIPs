package com.nmap.nMapScanner.controller;

import com.nmap.nMapScanner.model.ScanSession;
import com.nmap.nMapScanner.model.ScanSessionSummary;
import com.nmap.nMapScanner.model.ScannedIP;
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
    private IScannerService iScannerService;

    @Autowired
    private ScannedIPRepository scannedIPRepository;

    @GetMapping("/profiles")
    public String viewScanHistory(Model model) {
        Map<String, List<ScanSession>> groupedHistory = scanHistoryService.getScanHistoryGroupedByProfile();
        groupedHistory.values().forEach(Collections::reverse);

        model.addAttribute("scanHistory", groupedHistory);
        return "scanHistory";
    }


    @GetMapping("/profile/{name}")
    public String viewProfileDetails(@PathVariable String name, Model model) {
        // 1. Get scan sessions for the selected profile
        List<ScanSession> sessions = scanHistoryService.getScansForProfile(name);

        // 2. Get all grouped history
        Map<String, List<ScanSession>> groupedHistory = scanHistoryService.getScanHistoryGroupedByProfile();
        groupedHistory.values().forEach(Collections::reverse);

        // 3. Create summaries for the current profile
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

        // 4. Flatten all sessions to compute summary map
        List<ScanSession> allSessions = groupedHistory.values()
                .stream()
                .flatMap(List::stream)
                .toList();

        Map<Long, Map<String, Object>> summaryMap = scanHistoryService.getScanSummaries(allSessions);

        // 5. Compute up/down IPs for the selected profile only
        int upCount = 0;
        int downCount = 0;

        List<ScanSession> currentProfileSessions = groupedHistory.getOrDefault(name, List.of());

        for (ScanSession session : currentProfileSessions) {
            Map<String, Object> summary = summaryMap.get(session.getId());
            if (summary != null) {
                upCount += ((Number) summary.getOrDefault("upIPs", 0)).intValue();
                downCount += ((Number) summary.getOrDefault("downIPs", 0)).intValue();
            }
        }

        // 6. Add all required data to model
        model.addAttribute("profileName", name);
        model.addAttribute("scanSummaries", summaries);
        model.addAttribute("upCount", upCount);
        model.addAttribute("downCount", downCount);

        return "profile_details";
    }

}
