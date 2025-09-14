package sample.vuln;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;

@Controller
public class VulnerableOpenRedirect001 {

    // VULN: آدرس بازگشتی را مستقیماً از کاربر می‌گیرد
    // مثال: /go?url=https://evil.com
    @GetMapping("/go")
    public String go(@RequestParam String url) {
        return "redirect:" + url;
    }
}
