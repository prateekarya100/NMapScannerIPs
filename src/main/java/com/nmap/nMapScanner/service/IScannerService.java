package com.nmap.nMapScanner.service;

import com.nmap.nMapScanner.model.NMapScanData;

public interface IScannerService {
    void scanAndSave(NMapScanData nMapScanData);
}
