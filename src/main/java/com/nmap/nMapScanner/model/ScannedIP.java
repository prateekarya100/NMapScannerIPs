package com.nmap.nMapScanner.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ScannedIP {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String ipAddress;

    private String status; // "UP", "DOWN", etc.

    @ManyToOne
    @JoinColumn(name = "scan_session_id")
    private ScanSession scanSession;

    @OneToMany(mappedBy = "scannedIP", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ScannedPort> ports = new ArrayList<>();
}
