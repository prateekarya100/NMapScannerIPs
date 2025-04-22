package com.nmap.nMapScanner.controller;

import com.nmap.nMapScanner.model.ScanSession;
import com.nmap.nMapScanner.model.ScanSessionSummary;
import com.nmap.nMapScanner.service.ScanHistoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
@RequestMapping(value = "/dashboard")
public class DashboardController {

    @Autowired
    private ScanHistoryService scanHistoryService;

    @GetMapping("/profiles")
    public String viewScanHistory(Model model) {
        Map<String, List<ScanSession>> groupedHistory = scanHistoryService.getScanHistoryGroupedByProfile();
        model.addAttribute("scanHistory", groupedHistory);
//        groupedHistory.forEach((profile, sessions) -> {
//            System.out.println("=== Profile: " + profile + " ===");
//            sessions.forEach(s -> System.out.printf("Target: %s | Type: %s | Time: %s%n | All Scans on Range Of IP: %s ",
//                    s.getTarget(), s.getScanType(), s.getScanTime(),s.getJsonResult()));
//        });

        return "scanHistory";
    }

    @GetMapping("/profile/{name}")
    public String viewProfileDetails(@PathVariable String name, Model model) {
        // Fetch all scan sessions for the given profile
        List<ScanSession> sessions = scanHistoryService.getScansForProfile(name);

        // Convert to list of ScanSessionSummary, sorted by most recent scan first
        List<ScanSessionSummary> summaries = sessions.stream()
                .sorted(Comparator.comparing(ScanSession::getScanTime).reversed())
                .map(s -> new ScanSessionSummary(
                        s.getTarget(),
                        s.getScanType(),
                        s.getScanTime()
                ))
                .collect(Collectors.toList());

        // Add data to the model
        model.addAttribute("profileName", name);
        model.addAttribute("scanSummaries", summaries);

        return "profile_details";
    }


}
