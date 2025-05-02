package com.nmap.nMapScanner.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Entity
@AllArgsConstructor @NoArgsConstructor
@ToString
public class ScanSession {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String target;
    private String scanType;

    private LocalDateTime scanTime;

    @Lob
    private String jsonResult;

    private String profile;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_data_id")
    private NMapScanData scanData;

    private int openPorts;

    private int closedPorts;

    private int filteredPorts;

//    public int countIpsWithData() {
//        if (jsonResult == null || jsonResult.trim().isEmpty()) {
//            return 0; // Return 0 if jsonResult is null or empty
//        }
//
//        try {
//            ObjectMapper objectMapper = new ObjectMapper();
//            Map<String, Object> jsonMap = objectMapper.readValue(jsonResult, Map.class);
//            int count = 0;
//
//            for (Map.Entry<String, Object> entry : jsonMap.entrySet()) {
//                // Check if the entry has scan data (like ports, etc.)
//                if (entry.getValue() instanceof List && !((List<?>) entry.getValue()).isEmpty()) {
//                    count++;
//                }
//            }
//
//            return count;
//        } catch (Exception e) {
//            e.printStackTrace();
//            return 0;
//        }
//    }
//
//    public int countIpsWithoutData() {
//        if (jsonResult == null || jsonResult.trim().isEmpty()) {
//            return 0; // Return 0 if jsonResult is null or empty
//        }
//
//        try {
//            ObjectMapper objectMapper = new ObjectMapper();
//            Map<String, Object> jsonMap = objectMapper.readValue(jsonResult, Map.class);
//            int count = 0;
//
//            for (Map.Entry<String, Object> entry : jsonMap.entrySet()) {
//                // Check if the entry has no scan data (empty list or null)
//                if (entry.getValue() == null || (entry.getValue() instanceof List && ((List<?>) entry.getValue()).isEmpty())) {
//                    count++;
//                }
//            }
//
//            return count;
//        } catch (Exception e) {
//            e.printStackTrace();
//            return 0;
//        }
//    }

}
