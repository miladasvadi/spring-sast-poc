package sample.secure;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class SafeOpenRedirect001 {

    // SAFE: فقط مسیر نسبی داخل برنامه اجازه دارد (مثلاً "/home")
    @GetMapping("/go-safe")
    public String goSafe(@RequestParam String url) {
        if (url == null || url.isBlank()) return "redirect:/";
        // اجازه فقط به مسیرهای نسبی داخلی
        if (url.startsWith("http://") || url.startsWith("https://")) {
            return "redirect:/"; // بلاک URL خارجی
        }
        if (!url.startsWith("/")) {
            return "redirect:/"; // فقط مسیرهایی که با / شروع می‌شوند
        }
        return "redirect:" + url;
    }
}
