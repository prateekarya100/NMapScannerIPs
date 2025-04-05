package com.nmap.nMapScanner.repository;

import com.nmap.nMapScanner.model.ScannedPort;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ScannedPortRepository extends JpaRepository<ScannedPort,Long> {
}
