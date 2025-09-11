package com.example.demo.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/")
public class HelloController {

    @GetMapping
    public String hello() {
        return "hello";
    }

    @PostMapping("/users")
    public String createUser(@RequestBody String body) {
        return body;
    }

    @GetMapping("/ping")
    public String ping() {
        return "pong";
    }
}
