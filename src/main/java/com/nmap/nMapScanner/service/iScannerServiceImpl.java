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
        session.setScanTime(LocalDateTime.now()); //  Start time only
        session.setScanType(nMapScanData.getScanType());
        session.setScanData(nMapScanData);
        scanSessionRepository.save(session); // Save without end time

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
                return;
            }

            String output = outputBuilder.toString();

            //This method sets scanEndTime and saves session again
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
            default -> "-sS -sV -p 1-1000 --reason -v";
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

        int scanStart = 1;
        int scanEnd = 1000;

        int openPortCount = 0;
        int closedPortCount = 0;
        int filteredPortCount = 0;

        for (String line : lines) {
            line = line.trim();

            if (line.startsWith("Nmap scan report for")) {
                String ip = line.replace("Nmap scan report for", "").trim();

                currentIP = scannedIPRepository.findByIpAddress(ip)
                        .orElseGet(() -> {
                            ScannedIP newIp = new ScannedIP();
                            newIp.setIpAddress(ip);
                            return newIp;
                        });

                currentIP.setScanSession(session);
                scannedIPRepository.save(currentIP);

                jsonResultMap.put(ip, new ArrayList<>());
                knownPorts.clear();
            }
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

                    version = version.replaceAll("(?i)ttl\\s*\\d+", "").trim();
                    if (version.isBlank()) {
                        version = "unknown";
                    }


                    knownPorts.add(port);
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

                    Map<String, String> portMap = new LinkedHashMap<>();
                    portMap.put("port", String.valueOf(port));
                    portMap.put("protocol", protocol);
                    portMap.put("state", state);
                    portMap.put("service", service);
                    portMap.put("version", version);
                    jsonResultMap.get(currentIP.getIpAddress()).add(portMap);

                    switch (state.toLowerCase()) {
                        case "open":
                            openPortCount++;
                            break;
                        case "closed":
                            closedPortCount++;
                            break;
                        case "filtered":
                            filteredPortCount++;
                            break;
                        case "open|filtered":
                            openPortCount++;
                            break;
                    }
                }
            }
            else if (line.startsWith("Not shown:") && line.contains("closed tcp ports")) {
                notShownClosedCount = extractClosedPortCount(line);
            }

            // Add implied closed ports per IP
            if (line.isEmpty() && currentIP != null && isTcpScan && notShownClosedCount > 0) {
                int impliedClosedPorts = 0;
                for (int port = scanStart; port <= scanEnd; port++) {
                    if (!knownPorts.contains(port)) {
                        ScannedPort closedPort = new ScannedPort();
                        closedPort.setPort(port);
                        closedPort.setProtocol("tcp");
                        closedPort.setState("closed");
                        closedPort.setService("unknown");
                        closedPort.setVersion("unknown");
                        closedPort.setScannedIP(currentIP);
                        closedPort.setScanSession(session);
                        scannedPortRepository.save(closedPort);

                        Map<String, String> portMap = new LinkedHashMap<>();
                        portMap.put("port", String.valueOf(port));
                        portMap.put("protocol", "tcp");
                        portMap.put("state", "closed");
                        portMap.put("service", "unknown");
                        portMap.put("version", "unknown");
                        jsonResultMap.get(currentIP.getIpAddress()).add(portMap);

                        impliedClosedPorts++;
                        if (impliedClosedPorts >= notShownClosedCount) break;
                    }
                }
                closedPortCount += impliedClosedPorts;
                currentIP = null;
                knownPorts.clear();
            }
        }

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonString = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonResultMap);
            session.setJsonResult(jsonString);
            session.setOpenPorts(openPortCount);
            session.setClosedPorts(scanEnd - openPortCount);
            session.setFilteredPorts(filteredPortCount);
            session.setScanEndTime(LocalDateTime.now());
            scanSessionRepository.save(session);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Debug logs
        System.out.println("Open Ports: " + openPortCount);
        System.out.println("Closed Ports: " + (scanEnd - openPortCount));
        System.out.println("Filtered Ports: " + filteredPortCount);
    }

    private int extractClosedPortCount(String line) {
        try {
            Pattern pattern = Pattern.compile("Not shown: (\\d+) closed tcp ports");
            Matcher matcher = pattern.matcher(line);
            if (matcher.find()) {
                return Integer.parseInt(matcher.group(1));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }
}
