package com.nmap.nMapScanner.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nmap.nMapScanner.model.PortInfoDto;
import com.nmap.nMapScanner.model.ScanSession;
import com.nmap.nMapScanner.model.ScanSessionSummary;
import com.nmap.nMapScanner.model.ScannedIpDto;
import com.nmap.nMapScanner.repository.ScanSessionRepository;
import com.nmap.nMapScanner.service.ScanHistoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import java.util.*;
import java.util.stream.Collectors;

@Controller
@RequestMapping(value = "/dashboard")
public class DashboardController {

    @Autowired
    private ScanHistoryService scanHistoryService;

    @Autowired
    private ScanSessionRepository scanSessionRepository;

    @GetMapping("/profiles")
    public String viewScanHistory(Model model) {
        Map<String, List<ScanSession>> groupedHistory = scanHistoryService.getScanHistoryGroupedByProfile();
        groupedHistory.values().forEach(Collections::reverse);

        model.addAttribute("scanHistory", groupedHistory);
        return "scanHistory";
    }


    @GetMapping("/profile/{name}")
    public String viewProfileDetails(@PathVariable String name, Model model) {
        // Get all scan sessions for the selected profile
        List<ScanSession> sessions = scanHistoryService.getScansForProfile(name);
        if (sessions.isEmpty()) {
            throw new RuntimeException("No sessions found for profile: " + name);
        }

        // Get latest scan session
        ScanSession session = sessions.get(sessions.size() - 1);

        // Get IP counts
        int ipsWithData = scanSessionRepository.countIpsWithData(session.getId());
        int ipsWithoutData = scanSessionRepository.countIpsWithoutData(session.getId());

        // Parse JSON and extract UP IPs
        String json = session.getJsonResult();
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode;
        try {
            jsonNode = objectMapper.readTree(json);
        } catch (Exception e) {
            throw new RuntimeException("Error parsing JSON", e);
        }

        List<String> validIps = new ArrayList<>();
        JsonNode finalJsonNode = jsonNode;

        // Collect UP IPs
        jsonNode.fieldNames().forEachRemaining(key -> {
            if (!key.contains("host down")) {
                JsonNode data = finalJsonNode.get(key);
                if (data.isArray() && !data.isEmpty()) {
                    validIps.add(key);
                }
            }
        });

        // Build DTO list
        List<ScannedIpDto> ipDtos = validIps.stream().map(ip -> {
            ScannedIpDto dto = new ScannedIpDto();
            dto.setIpAddress(ip);

            // Generate mock vulnerability levels
            Random random = new Random();
            dto.setLowVulners(Math.max(0, (int) (random.nextGaussian() * 5 + 15)));
            dto.setMediumVulners(Math.max(0, (int) (random.nextGaussian() * 3 + 7)));
            dto.setHighVulners(Math.max(0, (int) (random.nextGaussian() * 2 + 2)));

            // Extract port details
            List<PortInfoDto> ports = new ArrayList<>();
            JsonNode ipDataArray = finalJsonNode.get(ip);

            if (ipDataArray != null && ipDataArray.isArray()) {
                for (JsonNode portEntry : ipDataArray) {
                    if (portEntry.has("port") && portEntry.has("service") && portEntry.has("version")) {
                        String service = portEntry.path("service").asText("");
                        String version = portEntry.path("version").asText("");

                        // Filter out "unknown" or "no-response"
                        if (!"unknown".equalsIgnoreCase(service) &&
                                !"unknown".equalsIgnoreCase(version) &&
                                !"no-response".equalsIgnoreCase(version)) {

                            PortInfoDto portInfo = new PortInfoDto();
                            portInfo.setPort(String.valueOf(portEntry.path("port").asInt()));
                            portInfo.setService(service);
                            portInfo.setVersion(version);

                            ports.add(portInfo);
                        }
                    }
                }
            }

            dto.setPorts(ports);
            return dto;
        }).collect(Collectors.toList());

        // Flattened list to hold data for rendering in table
        List<PortInfoDto> portDetailsList = new ArrayList<>();

        validIps.forEach(ip -> {
            JsonNode ipDataArray = finalJsonNode.get(ip);
            if (ipDataArray != null && ipDataArray.isArray()) {
                // Iterate through all ports for each IP
                ipDataArray.forEach(portEntry -> {
                    // Check if port, service, and version are present and valid
                    if (portEntry.has("port") && portEntry.has("service") && portEntry.has("version") && portEntry.has("state")) {
                        String service = portEntry.path("service").asText();
                        String version = portEntry.path("version").asText();

                        // Exclude unknown or null hosts, services, or versions
                        if (!"unknown".equalsIgnoreCase(service) && !service.isEmpty() &&
                                !"unknown".equalsIgnoreCase(version) && !version.isEmpty()) {

                            String portState = portEntry.path("state").asText();

                            // Check if the port is open and not null
                            if ("open".equalsIgnoreCase(portState)) {
                                // Create PortDetailsDto with IP, Port, Service, and Version
                                PortInfoDto portDetails = new PortInfoDto();
                                portDetails.setIpAddress(ip);
                                portDetails.setPort(String.valueOf(portEntry.path("port").asInt()));
                                portDetails.setService(service);
                                portDetails.setVersion(version);

                                // Add to the list
                                portDetailsList.add(portDetails);
                            }
                        }
                    }
                });
            }
        });

        // Prepare scan summaries for history section
        List<ScanSessionSummary> summaries = sessions.stream()
                .sorted(Comparator.comparing(ScanSession::getScanTime).reversed())
                .map(s -> new ScanSessionSummary(
                        s.getTarget(),
                        s.getScanType(),
                        s.getScanTime(),
                        s.getOpenPorts(),
                        s.getClosedPorts(),
                        s.getFilteredPorts()
                ))
                .toList();

        // Send data to UI
        model.addAttribute("profileName", name);
        model.addAttribute("scanSummaries", summaries);
        model.addAttribute("upCount", ipsWithData);
        model.addAttribute("downCount", ipsWithoutData);
        model.addAttribute("upIpAddress", ipDtos);
        // Send the list of IP | PORT | SERVICES | VERSION
        model.addAttribute("portDetailsList", portDetailsList);

        return "profile_details";
    }


}
