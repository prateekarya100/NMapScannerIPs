package com.nmap.nMapScanner.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(value = "/scan")
public class DemoController {

    @GetMapping(value = "/common")
    public String getCommonUI(){
        return "common";
    }
}
