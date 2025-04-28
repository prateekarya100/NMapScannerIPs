package com.nmap.nMapScanner.service;

import com.nmap.nMapScanner.repository.ScanSessionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ScanSessionService {

    @Autowired
    private ScanSessionRepository scanSessionRepository;

}
