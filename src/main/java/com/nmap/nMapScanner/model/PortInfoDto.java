package com.nmap.nMapScanner.model;

import lombok.*;

@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class PortInfoDto {
    private String ipAddress;
    private String port;
    private String service;
    private String version;
    private String state;
}
