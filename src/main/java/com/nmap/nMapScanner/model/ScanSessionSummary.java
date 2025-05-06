package com.nmap.nMapScanner.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor @NoArgsConstructor
public class ScanSessionSummary {
    private String target;
    private String scanType;
    private LocalDateTime scanTime;
    private LocalDateTime scanEndTime;
    private int openPorts;
    private int closedPorts;
    private int filteredPorts;
}
