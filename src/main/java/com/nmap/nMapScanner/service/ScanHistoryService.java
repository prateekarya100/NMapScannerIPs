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

    public Map<String, List<ScanSession>> getScanHistoryGroupedByProfile() {
        List<ScanSession> sessions = scanSessionRepository.findAll();
        return sessions.stream()
                .sorted(Comparator.comparing(ScanSession::getScanTime))
                .collect(Collectors.groupingBy(ScanSession::getProfile, LinkedHashMap::new, Collectors.toList()));
    }

    public List<ScanSession> getScansForProfile(String name) {
      return scanSessionRepository.findAllByOrderByScanTimeDesc();
    }
}
