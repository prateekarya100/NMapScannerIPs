package com.nmap.nMapScanner.service;

import com.nmap.nMapScanner.model.ScanSession;
import com.nmap.nMapScanner.model.ScannedIP;
import com.nmap.nMapScanner.repository.ScanSessionRepository;
import com.nmap.nMapScanner.repository.ScannedIPRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class ScanHistoryService {

    @Autowired
    private ScanSessionRepository scanSessionRepository;

    @Autowired
    private ScannedIPRepository scannedIPRepository;

    // ✅ Get all scan sessions grouped by profile name (latest first)
    public Map<String, List<ScanSession>> getScanHistoryGroupedByProfile() {
        List<ScanSession> sessions = scanSessionRepository.findAll();

        return sessions.stream()
                .sorted(Comparator.comparing(ScanSession::getScanTime).reversed())
                .collect(Collectors.groupingBy(
                        s -> Optional.ofNullable(s.getProfile()).orElse("Unlabeled"),
                        LinkedHashMap::new,
                        Collectors.toList()
                ));
    }

    // ✅ Get all scans for a given profile (case-insensitive)
    public List<ScanSession> getScansForProfile(String profileName) {
        return scanSessionRepository.findByProfileIgnoreCase(profileName);
    }

    public Map<Long, Map<String, Object>> getScanSummaries(List<ScanSession> sessions) {
        Map<Long, Map<String, Object>> result = new HashMap<>();

        for (ScanSession session : sessions) {
            Long sessionId = session.getId();

            int open = session.getOpenPorts();
            int closed = session.getClosedPorts();
            int filtered = session.getFilteredPorts();

            List<ScannedIP> scannedIPs = scannedIPRepository.findByScanSession(session);
            long upCount = scannedIPs.stream().filter(ip -> "UP".equalsIgnoreCase(ip.getStatus())).count();
            long downCount = scannedIPs.stream().filter(ip -> "DOWN".equalsIgnoreCase(ip.getStatus())).count();

            Map<String, Object> summary = new HashMap<>();
            summary.put("openPorts", open);
            summary.put("closedPorts", closed);
            summary.put("filteredPorts", filtered);
            summary.put("totalIPsScanned", scannedIPs.size());
            summary.put("upIPs", upCount);
            summary.put("downIPs", downCount);

            result.put(sessionId, summary);
        }

        return result;
    }


}
