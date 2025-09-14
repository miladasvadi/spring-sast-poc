// CWE-327: Strong Crypto (SECURE)
// Demo: use BCrypt for password hashing.
package demo.secure;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@RestController
@RequestMapping("/api/secure/hash")
public class SafeWeakCrypto001 {

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @GetMapping("/bcrypt")
    public String bcrypt(@RequestParam String password) {
        // ✅ BCrypt with salt and work factor
        return encoder.encode(password);
    }
}
