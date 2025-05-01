package com.nmap.nMapScanner.controller;

import com.nmap.nMapScanner.model.ScanSession;
import com.nmap.nMapScanner.model.ScanSessionSummary;
import com.nmap.nMapScanner.model.ScannedIP;
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

        // Get latest scan session id or last scan for the selected profile
        Long sessionId = sessions.get(sessions.size() - 1).getId();

        // Fetch a last or latest scan from your ScanSession of profile
        ScanSession session = scanSessionRepository.findById(sessionId).orElseThrow(() -> new RuntimeException("Session not found"));

        // Get the count of IPs with scan data
        int ipsWithData = session.countIpsWithData();
        System.out.println("Number of IPs with scan data: " + ipsWithData);

        // Get the count of IPs without scan data
        int ipsWithoutData = session.countIpsWithoutData();
        System.out.println("Number of IPs without scan data (DOWN IPs): " + ipsWithoutData);

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

        // Add all required data to model
        model.addAttribute("profileName", name);
        model.addAttribute("scanSummaries", summaries);
        model.addAttribute("upCount", ipsWithData);
        model.addAttribute("downCount", ipsWithoutData);

        return "profile_details";
    }

}
