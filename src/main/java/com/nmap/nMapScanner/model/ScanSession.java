package com.nmap.nMapScanner.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Getter @Setter
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
}
