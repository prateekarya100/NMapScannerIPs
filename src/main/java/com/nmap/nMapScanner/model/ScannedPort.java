package com.nmap.nMapScanner.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString(exclude = {"scannedIP", "scanSession"})
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
    @JsonBackReference // Prevents infinite recursion
    private ScannedIP scannedIP;

    @ManyToOne
    @JoinColumn(name = "scan_session_id")
    @JsonIgnore
    private ScanSession scanSession;

}
