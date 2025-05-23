package com.nmap.nMapScanner.repository;

import com.nmap.nMapScanner.model.NMapScanData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface NMapScanDataRepo extends JpaRepository<NMapScanData,Long> {

    boolean existsByProfile(String profile);

    Optional<NMapScanData> findByProfile(String profileName);
}
