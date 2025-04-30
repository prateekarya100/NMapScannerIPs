package com.nmap.nMapScanner.repository;

import com.nmap.nMapScanner.model.ScanSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanSessionRepository extends JpaRepository<ScanSession,Long> {

    List<ScanSession> findByProfileIgnoreCase(String profile);

}
