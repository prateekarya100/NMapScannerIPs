package com.nmap.nMapScanner.controller;

import com.nmap.nMapScanner.model.NMapScanData;
import com.nmap.nMapScanner.service.IScannerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@Controller
@RequestMapping(value = "/scan")
public class ScanController {

    @Autowired
    private IScannerService scannerService;

    private static final Map<String, String> SCAN_PROFILES = Map.of(
            "ping scan", "nmap -sV -sn ",
            "quick scan", "nmap -sV -T4 -F ",
            "regular scan", "nmap -sV ",
            "intense scan", "nmap -sV -T4 -A -v ",
            "quick traceroute", "nmap -sV -sn --traceroute ",
            "intense udp", "nmap -sV -sS -sU -T4 -A -v ",
            "all tcp ports", "nmap -sV -p 1-65535 -T4 -A -v ",
            "no ping", "nmap -sV -T4 -A -v -Pn ",
            "quick plus", "nmap -sV -T4 -O -F --version-light ",
            "vulners", "nmap -sV --script vulners "
    );
    @GetMapping(value = "/web")
    public String webAppHandler(Model model){
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        NMapScanData nMapScanData = new NMapScanData();
//        nMapScanData.setUsername(authentication.getName());
        List<String> scanType = SCAN_PROFILES.keySet().stream().toList();
        model.addAttribute("scanType", scanType);
        model.addAttribute("nMapScanData", nMapScanData);
        return "rangeIP";
    }

    @GetMapping(value = "/scanned")
    public String scannedStatusHandler(Model model){
        return "scanned";
    }

    @PostMapping(value = "/form/submit")
    public String createScanProfile(@ModelAttribute("scanProfile") NMapScanData nMapScanData,
                                    Model model){
        System.out.println(nMapScanData);

        scannerService.scanAndSave(nMapScanData);
        return "redirect:/scan/scanned";
    }

}