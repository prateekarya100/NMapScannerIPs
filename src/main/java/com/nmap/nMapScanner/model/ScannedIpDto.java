package com.nmap.nMapScanner.model;

import lombok.*;

import java.util.List;

@Getter
@Setter
@ToString @AllArgsConstructor @NoArgsConstructor
public class ScannedIpDto {
    private String ipAddress;
    private int lowVulners;
    private int mediumVulners;
    private int highVulners;
    private List<PortInfoDto> ports;
}
