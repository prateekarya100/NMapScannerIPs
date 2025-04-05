package com.nmap.nMapScanner.repository;

import com.nmap.nMapScanner.model.NMapScanData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface NMapScanDataRepo extends JpaRepository<NMapScanData,Long> {
}
