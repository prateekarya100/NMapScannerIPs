package com.nmap.nMapScanner.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ScannedPort {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private int port;
    private String protocol;
    private String state;
    private String service;
    private String version;

    @ManyToOne
    @JoinColumn(name = "scanned_ip_id")
    private ScannedIP scannedIP;

    @ManyToOne
    @JoinColumn(name = "scan_session_id")
    private ScanSession scanSession;

}
