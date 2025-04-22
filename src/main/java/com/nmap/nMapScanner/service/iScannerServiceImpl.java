package com.nmap.nMapScanner.service;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.nmap.nMapScanner.model.NMapScanData;
import com.nmap.nMapScanner.model.ScanSession;
import com.nmap.nMapScanner.model.ScannedIP;
import com.nmap.nMapScanner.model.ScannedPort;
import com.nmap.nMapScanner.repository.NMapScanDataRepo;
import com.nmap.nMapScanner.repository.ScanSessionRepository;
import com.nmap.nMapScanner.repository.ScannedIPRepository;
import com.nmap.nMapScanner.repository.ScannedPortRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.util.*;

@Service
public class iScannerServiceImpl implements IScannerService{

    @Autowired
    private ScanSessionRepository scanSessionRepository;

    @Autowired
    private ScannedIPRepository scannedIPRepository;

    @Autowired
    private ScannedPortRepository scannedPortRepository;

    @Autowired
    private NMapScanDataRepo nMapScanDataRepo;

    @Override
    public void scanAndSave(NMapScanData nMapScanData) {

        // save scan input profile
        nMapScanDataRepo.save(nMapScanData);

        // Save initial session with reference to NMapScanData
        ScanSession session = new ScanSession();
        session.setTarget(nMapScanData.getTarget());
        session.setProfile(nMapScanData.getProfile());
        session.setScanTime(LocalDateTime.now());
        session.setScanType(nMapScanData.getScanType());
        session.setScanData(nMapScanData); // Associate NMapScanData (sets scan_data_id)
        scanSessionRepository.save(session);


        // Build command
        String command = buildNmapCommand(nMapScanData.getTarget(), nMapScanData.getProfile());
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
                System.err.println("Nmap command failed with exit code " + exitCode);
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
        String args = switch (profile.toLowerCase()) {
            case "ping scan" -> "-sV -sn -p 1-1000";
            case "quick scan" -> "-sS -sV -T4 -p 1-1000 -F --reason -v";
            case "regular scan" -> "-sS -sV -p 1-1000 --reason -v";
            case "intense scan" -> "-sS -sV -T4 -A -p 1-1000 -v --reason";
            case "quick traceroute" -> "-sV -sn -p 1-1000 --traceroute";
            case "intense udp" -> "-sS -sU -sV -T4 -A -p 1-1000 -v --reason";
            case "all tcp ports" -> "-sS -sV -p 1-65535 -T4 --reason -v";
            case "no ping" -> "-sS -sV -T4 -A -v -Pn -p 1-1000 --reason";
            case "quick plus" -> "-sS -sV -T4 -O -F --version-light -p 1-1000 --reason -v";
            case "vulners" -> "-sV --script vulners -p 1-1000 --reason -v";
            default -> "-sS -sV -p 1-1000 --reason -v"; // fallback
        };
        return "nmap " + args + " " + target;

    }

    private void parseAndSaveOutput(String output, ScanSession session) {
        String[] lines = output.split("\n");
        ScannedIP currentIP = null;

        Map<String, List<Map<String, String>>> jsonResultMap = new LinkedHashMap<>();
        Set<Integer> knownPorts = new HashSet<>();
        int notShownClosedCount = 0;
        boolean isTcpScan = false;

        int scanStart = 1;      // default port scan range
        int scanEnd = 1000;

        for (String line : lines) {
            line = line.trim();

            // Detect IP
            if (line.startsWith("Nmap scan report for")) {
                String ip = line.replace("Nmap scan report for", "").trim();
                currentIP = scannedIPRepository.findByIpAddress(ip)
                        .orElseGet(() -> {
                            ScannedIP newIp = new ScannedIP();
                            newIp.setIpAddress(ip);
                            return scannedIPRepository.save(newIp);
                        });

                jsonResultMap.put(ip, new ArrayList<>());
                knownPorts.clear();
            }

            // Match open/closed/filtered ports
            else if (line.matches("^\\d+/\\w+\\s+(open|closed|filtered)(\\s+\\S+.*)?")) {
                if (currentIP != null) {
                    String[] parts = line.split("\\s+", 5);
                    String[] portInfo = parts[0].split("/");
                    int port = Integer.parseInt(portInfo[0]);
                    String protocol = portInfo[1];
                    String state = parts[1];
                    String service = parts.length >= 3 ? parts[2] : "unknown";
                    String version = parts.length >= 5 ? parts[4] :
                            (parts.length >= 4 ? parts[3] : "unknown");

                    knownPorts.add(port);
                    if ("tcp".equalsIgnoreCase(protocol)) isTcpScan = true;

                    // Save to DB
                    ScannedPort scannedPort = new ScannedPort();
                    scannedPort.setPort(port);
                    scannedPort.setProtocol(protocol);
                    scannedPort.setState(state);
                    scannedPort.setService(service);
                    scannedPort.setVersion(version);
                    scannedPort.setScannedIP(currentIP);
                    scannedPort.setScanSession(session);
                    scannedPortRepository.save(scannedPort);

                    // Add to JSON
                    Map<String, String> portMap = new LinkedHashMap<>();
                    portMap.put("port", String.valueOf(port));
                    portMap.put("protocol", protocol);
                    portMap.put("state", state);
                    portMap.put("service", service);
                    portMap.put("version", version);
                    jsonResultMap.get(currentIP.getIpAddress()).add(portMap);
                }
            }

            // Extract count of closed ports not shown
            else if (line.startsWith("Not shown:") && line.contains("closed tcp ports")) {
                notShownClosedCount = extractClosedPortCount(line);
            }
        }

        // Add implied closed ports to DB
        if (currentIP != null && isTcpScan && notShownClosedCount > 0) {
            for (int port = scanStart; port <= scanEnd; port++) {
                if (!knownPorts.contains(port)) {
                    // Save to DB
                    ScannedPort closedPort = new ScannedPort();
                    closedPort.setPort(0);
                    closedPort.setProtocol("tcp");
                    closedPort.setState("closed");
                    closedPort.setService("unknown");
                    closedPort.setVersion("unknown");
                    closedPort.setScannedIP(currentIP);
                    closedPort.setScanSession(session);
                    scannedPortRepository.save(closedPort);

                    // Add to JSON
                    Map<String, String> portMap = new LinkedHashMap<>();
                    portMap.put("port", String.valueOf(0));
                    portMap.put("protocol", "tcp");
                    portMap.put("state", "closed");
                    portMap.put("service", "unknown");
                    portMap.put("version", "unknown");
                    jsonResultMap.get(currentIP.getIpAddress()).add(portMap);
                }
            }
        }

        // Save final JSON
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonString = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonResultMap);
            session.setJsonResult(jsonString);
            scanSessionRepository.save(session);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private int extractClosedPortCount(String line) {
        try {
            String[] parts = line.split(" ");
            for (int i = 0; i < parts.length; i++) {
                if (parts[i].equals("Not") && parts[i + 1].equals("shown:")) {
                    return Integer.parseInt(parts[i + 2]);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }

}
