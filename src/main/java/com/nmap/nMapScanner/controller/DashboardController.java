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

                        if (!"unknown".equalsIgnoreCase(service) &&
                                !"unknown".equalsIgnoreCase(version) &&
                                !"no-response".equalsIgnoreCase(version)) {

                            PortInfoDto portInfo = new PortInfoDto();
                            String protocol = portEntry.has("protocol") ? portEntry.path("protocol").asText("tcp") : "tcp";
                            String portWithProtocol = portEntry.path("port").asText() + "/" + protocol;

                            portInfo.setPort(portWithProtocol);
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
                ipDataArray.forEach(portEntry -> {
                    if (portEntry.has("port") && portEntry.has("service") &&
                            portEntry.has("version") && portEntry.has("state")) {

                        String service = portEntry.path("service").asText();
                        String version = portEntry.path("version").asText();
                        String portState = portEntry.path("state").asText();

                        if (!"unknown".equalsIgnoreCase(service) && !service.isEmpty() &&
                                !"unknown".equalsIgnoreCase(version) && !version.isEmpty() &&
                                ("open".equalsIgnoreCase(portState) || "filtered".equalsIgnoreCase(portState))) {

                            PortInfoDto portDetails = new PortInfoDto();
                            portDetails.setIpAddress(ip);

                            String protocol = portEntry.has("protocol") ? portEntry.path("protocol").asText("tcp") : "tcp";
                            String portWithProtocol = portEntry.path("port").asText() + "/" + protocol;

                            portDetails.setPort(portWithProtocol);
                            portDetails.setService(service);
                            portDetails.setVersion(version);
                            portDetails.setState(portState);

                            portDetailsList.add(portDetails);
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
        model.addAttribute("portDetailsList", portDetailsList);

        return "profile_details";
    }

}
