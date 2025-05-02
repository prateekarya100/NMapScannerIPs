package com.nmap.nMapScanner.repository;


import com.nmap.nMapScanner.model.ScanSession;
import com.nmap.nMapScanner.model.ScannedIP;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanSessionRepository extends JpaRepository<ScanSession,Long> {

    List<ScanSession> findByProfileIgnoreCase(String profile);

    @Query("SELECT COUNT(DISTINCT ip.id) FROM ScannedIP ip JOIN ip.ports p WHERE ip.scanSession.id = :sessionId")
    int countIpsWithData(@Param("sessionId") Long sessionId);

    @Query("SELECT COUNT(ip) FROM ScannedIP ip LEFT JOIN ip.ports p WHERE ip.scanSession.id = :sessionId AND p.id IS NULL")
    int countIpsWithoutData(@Param("sessionId") Long sessionId);

    @Query("SELECT DISTINCT ip FROM ScannedIP ip LEFT JOIN FETCH ip.ports WHERE ip.scanSession.id = :sessionId AND ip.status = 'UP'")
    List<ScannedIP> findUpIpsWithPortData(@Param("sessionId") Long sessionId);


}
