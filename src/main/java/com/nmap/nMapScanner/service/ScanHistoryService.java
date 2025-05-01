package com.nmap.nMapScanner.service;

import com.nmap.nMapScanner.model.ScanSession;
import com.nmap.nMapScanner.repository.ScanSessionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class ScanHistoryService {

    @Autowired
    private ScanSessionRepository scanSessionRepository;

    // Get all scan sessions grouped by profile name (latest first)
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

    // Get all scans for a given profile (case-insensitive)
    public List<ScanSession> getScansForProfile(String profileName) {
        return scanSessionRepository.findByProfileIgnoreCase(profileName);
    }

}
