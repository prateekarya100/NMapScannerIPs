package com.nmap.nMapScanner.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@ToString @AllArgsConstructor @NoArgsConstructor
public class ScannedIpDto {
    private String ipAddress;
    private int lowVulners;
    private int mediumVulners;
    private int highVulners;
}
