package com.nmap.nMapScanner;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
@EnableJpaAuditing(auditorAwareRef = "AuditAwareImpl")
public class NMapScannerApplication {

	public static void main(String[] args) {
		SpringApplication.run(NMapScannerApplication.class, args);
	}

}
