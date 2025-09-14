// CWE-502: Safe alternative (SECURE)
// Demo: use JSON binding into a DTO instead of Java deserialization.
package demo.secure;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/secure/deserialize")
public class SafeDeserialize001 {

    public static class UserDTO {
        public String username;
        public String role;
    }

    @PostMapping(consumes = "application/json", produces = "text/plain")
    public String load(@RequestBody UserDTO dto) {
        // ✅ only maps to a known, simple DTO (no Java deserialization)
        return "User: " + dto.username + " (" + dto.role + ")";
    }
}
