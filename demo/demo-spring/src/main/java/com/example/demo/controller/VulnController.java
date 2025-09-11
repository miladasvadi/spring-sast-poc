package com.example.demo.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/")
public class VulnController {

    // CWE-78: OS Command Injection (عمداً ناامن)
    @PostMapping("/")
    public String exec(@RequestParam("cmd") String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(cmd); // <-- sink
        p.getOutputStream().close();
        p.getInputStream().close();
        p.getErrorStream().close();
        return "OK";
    }

    // CWE-22: Path Traversal (عمداً ناامن)
    @GetMapping("/")
    public String read(@RequestParam("path") String path) throws Exception {
        java.io.FileInputStream fis = new java.io.FileInputStream(path); // <-- sink
        fis.close();
        return "OK";
    }
}
