package com.nmap.nMapScanner.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nmap.nMapScanner.model.NMapScanData;
import com.nmap.nMapScanner.model.ScanSession;
import com.nmap.nMapScanner.model.ScannedIP;
import com.nmap.nMapScanner.model.ScannedPort;
import com.nmap.nMapScanner.repository.ScanSessionRepository;
import com.nmap.nMapScanner.repository.ScannedIPRepository;
import com.nmap.nMapScanner.repository.ScannedPortRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class iScannerServiceImpl implements IScannerService{

    @Autowired
    private ScanSessionRepository scanSessionRepository;

    @Autowired
    private ScannedIPRepository scannedIPRepository;

    @Autowired
    private ScannedPortRepository scannedPortRepository;

    @Override
    public void scanAndSave(NMapScanData scanData) {
        // Save initial session
        ScanSession session = new ScanSession();
        session.setTarget(scanData.getTarget());
        session.setProfile(scanData.getProfile());
        session.setScanTime(LocalDateTime.now());
        scanSessionRepository.save(session);

        // Build command
        String command = buildNmapCommand(scanData.getTarget(), scanData.getProfile());
        System.out.println("Executing Nmap command: " + command);

        try {
            // Windows compatible process builder
            ProcessBuilder builder = new ProcessBuilder("cmd.exe", "/c", command);
            builder.redirectErrorStream(true);
            Process process = builder.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder outputBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("[Nmap Output] " + line);
                outputBuilder.append(line).append("\n");
            }

            int exitCode = process.waitFor();
            if (exitCode != 0) {
                System.err.println("❌ Nmap command failed with exit code " + exitCode);
                return;
            }

            String output = outputBuilder.toString();

            // Parse and store
            parseAndSaveOutput(output, session);

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    private String buildNmapCommand(String target, String profile) {
        String args;
        switch (profile.toLowerCase()) {
            case "ping scan":
                args = "-sV -sn";
                break;
            case "quick scan":
                args = "-sV -T4 -F";
                break;
            case "regular scan":
                args = "-sV";
                break;
            case "intense scan":
                args = "-sV -T4 -A -v";
                break;
            case "quick traceroute":
                args = "-sV -sn --traceroute";
                break;
            case "intense udp":
                args = "-sV -sS -sU -T4 -A -v";
                break;
            case "all tcp ports":
                args = "-sV -p 1-65535 -T4 -A -v";
                break;
            case "no ping":
                args = "-sV -T4 -A -v -Pn";
                break;
            case "quick plus":
                args = "-sV -T4 -O -F --version-light";
                break;
            case "vulners":
                args = "-sV --script vulners";
                break;
            default:
                args = "-sV"; // fallback
        }
        return "nmap " + args + " " + target;
    }

//    private void parseAndSaveOutput(String output, ScanSession session) {
//        String[] lines = output.split("\n");
//        ScannedIP currentIP = null;
//
//        for (String line : lines) {
//            line = line.trim();
//
//            if (line.startsWith("Nmap scan report for")) {
//                String ip = line.replace("Nmap scan report for", "").trim();
//                currentIP = new ScannedIP();
//                currentIP.setIpAddress(ip);
//                currentIP.setScanSession(session);
//                scannedIPRepository.save(currentIP);
//
//            } else if (line.matches("^\\d+/\\w+\\s+open.*")) {
//                if (currentIP != null) {
//                    String[] parts = line.split("\\s+");
//                    String[] portInfo = parts[0].split("/");
//                    int port = Integer.parseInt(portInfo[0]);
//                    String protocol = portInfo[1];
//                    String service = parts.length > 2 ? parts[2] : "unknown";
//
//                    ScannedPort scannedPort = new ScannedPort();
//                    scannedPort.setPort(port);
//                    scannedPort.setProtocol(protocol);
//                    scannedPort.setService(service);
//                    scannedPort.setScannedIP(currentIP);
//
//                    scannedPortRepository.save(scannedPort);
//                }
//            }
//        }
//    }


    private void parseAndSaveOutput(String output, ScanSession session) {
        String[] lines = output.split("\n");
        ScannedIP currentIP = null;

        // To build JSON result
        Map<String, List<Map<String, String>>> jsonResultMap = new LinkedHashMap<>();

        for (String line : lines) {
            line = line.trim();

            // Match IP line
            if (line.startsWith("Nmap scan report for")) {
                String ip = line.replace("Nmap scan report for", "").trim();
               currentIP = scannedIPRepository.findByIpAddress(ip)
        .orElseGet(() -> {
            ScannedIP newIp = new ScannedIP();
            newIp.setIpAddress(ip);
            return scannedIPRepository.save(newIp);
        });

                jsonResultMap.put(ip, new ArrayList<>());

                // Match port line with service and version
            } else if (line.matches("^\\d+/\\w+\\s+\\w+\\s+.*")) {
                if (currentIP != null) {
                    String[] parts = line.split("\\s+", 5); // Limit to 5 parts for version info

                    // Example: "80/tcp open http Apache httpd 2.4.41"
                    String[] portInfo = parts[0].split("/");
                    int port = Integer.parseInt(portInfo[0]);
                    String protocol = portInfo[1];
                    String state = parts[1];
                    String service = parts[2];
                    String version = parts.length >= 5 ? parts[4] : (parts.length >= 4 ? parts[3] : "unknown");

                    // Save to DB
                    ScannedPort scannedPort = new ScannedPort();
                    scannedPort.setPort(port);
                    scannedPort.setProtocol(protocol);
                    scannedPort.setState(state);
                    scannedPort.setService(service);
                    scannedPort.setVersion(version);
                    scannedPort.setScannedIP(currentIP);
                    scannedPort.setScanSession(session); // ✅ FIXED
                    scannedPortRepository.save(scannedPort);


                    // Add to JSON map
                    Map<String, String> portMap = new LinkedHashMap<>();
                    portMap.put("port", String.valueOf(port));
                    portMap.put("protocol", protocol);
                    portMap.put("state", state);
                    portMap.put("service", service);
                    portMap.put("version", version);
                    jsonResultMap.get(currentIP.getIpAddress()).add(portMap);
                }
            }
        }

        // Convert map to JSON and save to session
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonString = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonResultMap);
            session.setJsonResult(jsonString);
            scanSessionRepository.save(session);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}
