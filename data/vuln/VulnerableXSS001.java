package sample.vuln;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.MediaType;

@RestController
public class VulnerableXSS001 {

    // VULN: بازگرداندن ورودی کاربر به صورت HTML بدون escape
    @GetMapping(value = "/echo", produces = MediaType.TEXT_HTML_VALUE)
    public String echo(@RequestParam String q) {
        return "<h1>Echo:</h1>" + q; // اگر q شامل <script> باشد اجرا می‌شود
    }
}
