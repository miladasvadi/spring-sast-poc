# -*- coding: utf-8 -*-
"""
make_demo_spring_project.py
یک پروژهٔ Spring دمو می‌سازد: HelloController , UserController , VulnController
استفاده:
    python tools/make_demo_spring_project.py --out demo/demo-spring
"""

import os
import argparse

def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="مسیر خروجی پروژهٔ دمو (پوشهٔ مقصد)")
    args = ap.parse_args()

    out_root = os.path.abspath(args.out)
    src_root = os.path.join(out_root, "src", "main", "java", "com", "example", "demo")
    ctrl_pkg = os.path.join(src_root, "controller")

    # ساختار پوشه
    os.makedirs(ctrl_pkg, exist_ok=True)

    # فایل placeholder برای اپلیکیشن (برای اینکه پروژه خالی نباشه)
    app_java = """package com.example.demo;

public class DemoApplication {
    public static void main(String[] args) {
        System.out.println("Demo Spring app placeholder");
    }
}
"""
    write(os.path.join(src_root, "DemoApplication.java"), app_java)

    hello_ctrl = """package com.example.demo.controller;

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
"""
    write(os.path.join(ctrl_pkg, "HelloController.java"), hello_ctrl)

    user_ctrl = """package com.example.demo.controller;

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
"""
    write(os.path.join(ctrl_pkg, "UserController.java"), user_ctrl)

    vuln_ctrl = """package com.example.demo.controller;

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
"""
    write(os.path.join(ctrl_pkg, "VulnController.java"), vuln_ctrl)

    print("[OK] Demo Spring project created at:")
    print(out_root)

if __name__ == "__main__":
    main()
