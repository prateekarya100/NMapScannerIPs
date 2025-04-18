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

//    private static final Map<String, String> SCAN_PROFILES = Map.of(
//            "ping scan", "nmap -sV -sn ",
//            "quick scan", "nmap -sV -T4 -F ",
//            "regular scan", "nmap -sV ",
//            "intense scan", "nmap -sV -T4 -A -v ",
//            "quick traceroute", "nmap -sV -sn --traceroute ",
//            "intense udp", "nmap -sV -sS -sU -T4 -A -v ",
//            "all tcp ports", "nmap -sV -p 1-65535 -T4 -A -v ",
//            "no ping", "nmap -sV -T4 -A -v -Pn ",
//            "quick plus", "nmap -sV -T4 -O -F --version-light ",
//            "vulners", "nmap -sV --script vulners "
//    );

    private static final Map<String, String> SCAN_PROFILES = Map.of(
            "ping scan", "nmap -sV -sn -p 1-1000",
            "quick scan", "nmap -sS -sV -T4 -p 1-1000 -F --reason -v",
            "regular scan", "nmap -sS -sV -p 1-1000 --reason -v",
            "intense scan", "nmap -sS -sV -T4 -A -p 1-1000 -v --reason",
            "quick traceroute", "nmap -sV -sn -p 1-1000 --traceroute",
            "intense udp", "nmap -sS -sU -sV -T4 -A -p 1-1000 -v --reason",
            "all tcp ports", "nmap -sS -sV -p 1-65535 -T4 --reason -v",
            "no ping", "nmap -sS -sV -T4 -A -v -Pn -p 1-1000 --reason",
            "quick plus", "nmap -sS -sV -T4 -O -F --version-light -p 1-1000 --reason -v",
            "vulners", "nmap -sV --script vulners -p 1-1000 --reason -v"
    );

    @GetMapping(value = "/web")
    public String webAppHandler(Model model){
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        NMapScanData nMapScanData = new NMapScanData();
//        nMapScanData.setUsername(authentication.getName());
        List<String> scanTypes = SCAN_PROFILES.keySet().stream().toList();
        model.addAttribute("scanTypes", scanTypes);
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
//        System.out.println(nMapScanData);

        scannerService.scanAndSave(nMapScanData);
        return "redirect:/dashboard/profiles";
    }


}