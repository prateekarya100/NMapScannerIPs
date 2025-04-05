package com.nmap.nMapScanner.repository;

import com.nmap.nMapScanner.model.ScanSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ScanSessionRepository extends JpaRepository<ScanSession,Long> {
}
