package com.nmap.nMapScanner.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nmap.nMapScanner.model.*;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class iScannerServiceImpl implements IScannerService {

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
        nMapScanDataRepo.save(nMapScanData);

        ScanSession session = new ScanSession();
        session.setTarget(nMapScanData.getTarget());
        session.setProfile(nMapScanData.getProfile());
        session.setScanTime(LocalDateTime.now());
        session.setScanType(nMapScanData.getScanType());
        session.setScanData(nMapScanData);
        session.setStatus(ScanStatus.IN_PROGRESS); // 👈 Set status when starting scan
        scanSessionRepository.save(session);

        String command = buildNmapCommand(nMapScanData.getTarget(), nMapScanData.getProfile());
        System.out.println("Executing Nmap command: " + command);

        try {
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
                session.setStatus(ScanStatus.FAILED); // 👈 Mark as FAILED
                scanSessionRepository.save(session);
                return;
            }

            String output = outputBuilder.toString();
            parseAndSaveOutput(output, session); // Parse will update session JSON

            // After successful parsing
            session.setStatus(ScanStatus.COMPLETED); // 👈 Mark as COMPLETED
            scanSessionRepository.save(session);

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            session.setStatus(ScanStatus.FAILED); // 👈 Mark as FAILED if exception
            scanSessionRepository.save(session);
            Thread.currentThread().interrupt(); // Good practice if InterruptedException
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
            default -> "-sS -sV -p 1-1000 --reason -v";
        };
        return "nmap " + args + " " + target;
    }

    private void parseAndSaveOutput(String output, ScanSession session) {
        String[] lines = output.split("\n");
        ScannedIP currentIP = null;

        Map<String, List<Map<String, String>>> jsonResultMap = new LinkedHashMap<>();
        Set<Integer> detectedPorts = new HashSet<>();
        boolean isTcpScan = false;
        int notShownClosedCount = 0;

        int scanStart = 1;
        int scanEnd = 1000;

        int openPorts = 0;
        int closedPorts = 0;
        int filteredPorts = 0;

        for (String rawLine : lines) {
            String line = rawLine.trim();

            if (line.startsWith("Nmap scan report for")) {
                String ipAddress = line.replace("Nmap scan report for", "").trim();
                currentIP = scannedIPRepository.findByIpAddress(ipAddress)
                        .orElseGet(() -> {
                            ScannedIP newIp = new ScannedIP();
                            newIp.setIpAddress(ipAddress);
                            return scannedIPRepository.save(newIp);
                        });
                jsonResultMap.put(ipAddress, new ArrayList<>());
                detectedPorts.clear();
            }

            else if (line.matches("^\\d+/\\w+\\s+(open|closed|filtered)(\\s+\\S+.*)?")) {
                if (currentIP != null) {
                    String[] parts = line.split("\\s+", 5);
                    String[] portInfo = parts[0].split("/");
                    int port = Integer.parseInt(portInfo[0]);
                    String protocol = portInfo[1];
                    String state = parts[1];
                    String service = (parts.length >= 3) ? parts[2] : "unknown";
                    String version = (parts.length >= 5) ? parts[4] :
                            (parts.length >= 4) ? parts[3] : "unknown";

                    detectedPorts.add(port);
                    if ("tcp".equalsIgnoreCase(protocol)) isTcpScan = true;

                    ScannedPort scannedPort = new ScannedPort();
                    scannedPort.setPort(port);
                    scannedPort.setProtocol(protocol);
                    scannedPort.setState(state);
                    scannedPort.setService(service);
                    scannedPort.setVersion(version);
                    scannedPort.setScannedIP(currentIP);
                    scannedPort.setScanSession(session);
                    scannedPortRepository.save(scannedPort);

                    Map<String, String> portDetails = new LinkedHashMap<>();
                    portDetails.put("port", String.valueOf(port));
                    portDetails.put("protocol", protocol);
                    portDetails.put("state", state);
                    portDetails.put("service", service);
                    portDetails.put("version", version);
                    jsonResultMap.get(currentIP.getIpAddress()).add(portDetails);

                    switch (state.toLowerCase()) {
                        case "open" -> openPorts++;
                        case "closed" -> closedPorts++;
                        case "filtered" -> filteredPorts++;
                    }
                }
            }

            else if (line.startsWith("Not shown:") && line.contains("closed tcp ports")) {
                notShownClosedCount = extractClosedPortCount(line);
            }
        }

        // Handle implied closed TCP ports
        if (currentIP != null && isTcpScan && notShownClosedCount > 0) {
            int closedAdded = 0;
            for (int port = scanStart; port <= scanEnd && closedAdded < notShownClosedCount; port++) {
                if (!detectedPorts.contains(port)) {
                    ScannedPort impliedClosedPort = new ScannedPort();
                    impliedClosedPort.setPort(port);
                    impliedClosedPort.setProtocol("tcp");
                    impliedClosedPort.setState("closed");
                    impliedClosedPort.setService("unknown");
                    impliedClosedPort.setVersion("unknown");
                    impliedClosedPort.setScannedIP(currentIP);
                    impliedClosedPort.setScanSession(session);
                    scannedPortRepository.save(impliedClosedPort);

                    Map<String, String> closedPortMap = new LinkedHashMap<>();
                    closedPortMap.put("port", String.valueOf(port));
                    closedPortMap.put("protocol", "tcp");
                    closedPortMap.put("state", "closed");
                    closedPortMap.put("service", "unknown");
                    closedPortMap.put("version", "unknown");
                    jsonResultMap.get(currentIP.getIpAddress()).add(closedPortMap);

                    closedPorts++;
                    closedAdded++;
                }
            }
        }

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonString = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonResultMap);
            session.setJsonResult(jsonString);
            session.setOpenPorts(openPorts);
            session.setClosedPorts(closedPorts);
            session.setFilteredPorts(filteredPorts);
            scanSessionRepository.save(session);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("Summary: Open=" + openPorts + ", Closed=" + closedPorts + ", Filtered=" + filteredPorts);
    }

    private int extractClosedPortCount(String line) {
        try {
            Matcher matcher = Pattern.compile("Not shown: (\\d+) closed tcp ports").matcher(line);
            if (matcher.find()) {
                return Integer.parseInt(matcher.group(1));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }
}
