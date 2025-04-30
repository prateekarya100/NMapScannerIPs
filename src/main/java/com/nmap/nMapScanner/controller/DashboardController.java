package com.nmap.nMapScanner.controller;

import com.nmap.nMapScanner.model.ScanSession;
import com.nmap.nMapScanner.model.ScanSessionSummary;
import com.nmap.nMapScanner.model.ScannedIP;
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

    @GetMapping("/profiles")
    public String viewScanHistory(Model model) {
        // Get the grouped history of scan sessions
        Map<String, List<ScanSession>> groupedHistory = scanHistoryService.getScanHistoryGroupedByProfile();
        groupedHistory.values().forEach(Collections::reverse); // Reverse the history for latest first
        model.addAttribute("scanHistory", groupedHistory);

        // Check if there are any scan sessions
        if (!groupedHistory.isEmpty()) {
            // Get the profile name (first one in the grouped history)
            String profileName = groupedHistory.keySet().iterator().next();
            List<ScanSession> sessions = groupedHistory.get(profileName);

            if (sessions != null && !sessions.isEmpty()) {
                // Get the latest session ID
                Long sessionId = sessions.get(0).getId();

                // Fetch the counts of UP and DOWN IPs from the service
                Map<String, Integer> statusCounts = iScannerService.getIPStatusCounts(sessionId);
                System.out.println("statusCounts :: "+statusCounts);
                // Add UP and DOWN counts to the model
                model.addAttribute("hostUpCount", statusCounts.get("up"));
                model.addAttribute("hostDownCount", statusCounts.get("down"));
            } else {
                // If no sessions, set default counts
                model.addAttribute("hostUpCount", 0);
                model.addAttribute("hostDownCount", 0);
            }
        } else {
            // If no history available, set default counts
            model.addAttribute("hostUpCount", 0);
            model.addAttribute("hostDownCount", 0);
        }

        // Return the view name
        return "scanHistory";
    }



    @GetMapping("/profile/{name}")
    public String viewProfileDetails(@PathVariable String name, Model model) {
        List<ScanSession> sessions = scanHistoryService.getScansForProfile(name);

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
                .collect(Collectors.toList());

        model.addAttribute("profileName", name);
        model.addAttribute("scanSummaries", summaries);

        return "profile_details";
    }
}
