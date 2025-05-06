package com.nmap.nMapScanner.repository;


import com.nmap.nMapScanner.model.ScanSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ScanSessionRepository extends JpaRepository<ScanSession,Long> {

    List<ScanSession> findByProfileIgnoreCase(String profile);

    @Query("SELECT COUNT(DISTINCT ip.id) FROM ScannedIP ip JOIN ip.ports p WHERE ip.scanSession.id = :sessionId")
    int countIpsWithData(@Param("sessionId") Long sessionId);

    @Query("SELECT COUNT(ip) FROM ScannedIP ip LEFT JOIN ip.ports p WHERE ip.scanSession.id = :sessionId AND p.id IS NULL")
    int countIpsWithoutData(@Param("sessionId") Long sessionId);

    List<ScanSession> findScanSessionsByProfile(String name);

}
