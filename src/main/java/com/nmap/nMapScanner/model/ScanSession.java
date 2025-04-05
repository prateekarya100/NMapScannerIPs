package com.nmap.nMapScanner.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Getter @Setter
@AllArgsConstructor @NoArgsConstructor
public class ScanSession {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String target;
    private String profile;

    private LocalDateTime scanTime;

    @OneToMany(mappedBy = "scanSession", cascade = CascadeType.ALL,orphanRemoval = true)
    private List<ScannedIP> scannedIPs = new ArrayList<>();
}
