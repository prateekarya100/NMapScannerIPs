package com.nmap.nMapScanner.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Data
@Entity
@AllArgsConstructor @NoArgsConstructor
public class ScanSession {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String target;
    private String scanType;

    private LocalDateTime scanTime;

//    @OneToMany(mappedBy = "scanSession", cascade = CascadeType.ALL,orphanRemoval = true)
//    private List<ScannedIP> scannedIPs = new ArrayList<>();

    @Lob
    private String jsonResult;

    private String profile;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_data_id")
    private NMapScanData scanData;

    private int openPorts;

    private int closedPorts;

    private int filteredPorts;
}
