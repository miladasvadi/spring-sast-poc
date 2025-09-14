// CWE-327: Weak Crypto (VULN)
// Demo: hashes passwords with MD5 (insecure).
package demo.vuln;

import org.springframework.web.bind.annotation.*;
import java.security.MessageDigest;

@RestController
@RequestMapping("/api/vuln/hash")
public class VulnWeakCrypto001 {

    @GetMapping("/md5")
    public String md5(@RequestParam String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // ❌ weak
        byte[] digest = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
