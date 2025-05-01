package com.nmap.nMapScanner.service;

import com.nmap.nMapScanner.model.NMapScanData;
import org.springframework.scheduling.annotation.Async;

public interface IScannerService {

    @Async
    void scanAndSave(NMapScanData nMapScanData);

}
