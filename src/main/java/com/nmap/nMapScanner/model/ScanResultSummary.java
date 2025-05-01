package com.nmap.nMapScanner.model;

import jakarta.persistence.Entity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class ScanResultSummary {
    private int totalIPs;
    private int upIPs;
    private int downIPs;
}
