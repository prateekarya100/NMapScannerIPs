package com.nmap.nMapScanner.service;

import com.nmap.nMapScanner.model.NMapScanData;
import com.nmap.nMapScanner.model.ScannedIP;
import org.springframework.scheduling.annotation.Async;

import java.util.List;
import java.util.Map;

public interface IScannerService {

    @Async
    void scanAndSave(NMapScanData nMapScanData);

}
