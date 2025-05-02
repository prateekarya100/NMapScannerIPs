package com.nmap.nMapScanner.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString(exclude = {"scanSession", "ports"})
public class ScannedIP {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String ipAddress;
    private String status;

    @ManyToOne
    @JoinColumn(name = "scan_session_id")
    @JsonBackReference // Prevents infinite recursion
    private ScanSession scanSession;

    @OneToMany(mappedBy = "scannedIP", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference // Marks the forward part of the relationship
    private List<ScannedPort> ports = new ArrayList<>();
}
