package com.example.demo.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    @PutMapping("/")
    public String update(@RequestBody String body) {
        return body;
    }

    @DeleteMapping("/{id}")
    public String delete(@PathVariable("id") String id) {
        return id;
    }
}
