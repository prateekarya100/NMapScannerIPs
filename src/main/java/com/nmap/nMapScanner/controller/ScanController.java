package com.nmap.nMapScanner.controller;

import com.nmap.nMapScanner.model.NMapScanData;
import com.nmap.nMapScanner.repository.NMapScanDataRepo;
import com.nmap.nMapScanner.service.IScannerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Controller
@RequestMapping(value = "/scan")
public class ScanController {

    @Autowired
    private IScannerService scannerService;

    @Autowired
    private NMapScanDataRepo nmapScanDataRepository;

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

    @PostMapping(value = "/form/submit")
    public String createScanProfile(@ModelAttribute("scanProfile") NMapScanData nMapScanData,
                                    Model model){
        if (nmapScanDataRepository.existsByProfile(nMapScanData.getProfile())) {
            model.addAttribute("nMapScanData", nMapScanData);
            List<String> scanTypes = SCAN_PROFILES.keySet().stream().toList();
            model.addAttribute("scanTypes", scanTypes);
            model.addAttribute("error", "Profile name already exists. Please choose another.");
                return "rangeIP"; // view name
        }

        scannerService.scanAndSave(nMapScanData);
        return "redirect:/dashboard/profiles";
    }

    @PostMapping("/rescan")
    public String rescanProfile(@RequestParam("profile") String profileName, RedirectAttributes redirectAttributes) {
        Optional<NMapScanData> optionalProfile = nmapScanDataRepository.findByProfile(profileName);

        if (optionalProfile.isPresent()) {
            scannerService.scanAndSave(optionalProfile.get());
            redirectAttributes.addFlashAttribute("message", "Re-scan started for profile: " + profileName);
        } else {
            redirectAttributes.addFlashAttribute("error", "Profile not found: " + profileName);
        }

        return "redirect:/dashboard/profiles";
    }

}