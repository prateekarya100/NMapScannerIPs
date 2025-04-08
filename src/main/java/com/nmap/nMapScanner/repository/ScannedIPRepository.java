package com.nmap.nMapScanner.repository;

import com.nmap.nMapScanner.model.ScannedIP;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ScannedIPRepository extends JpaRepository<ScannedIP,Long> {
    Optional<ScannedIP> findByIpAddress(String ip);
}
