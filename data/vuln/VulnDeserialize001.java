// CWE-502: Unsafe Deserialization (VULN)
// Demo: accepts a Base64-encoded Java-serialized blob and deserializes it directly.
package demo.vuln;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/api/vuln/deserialize")
public class VulnDeserialize001 {

    @PostMapping
    public String load(@RequestParam("blob") String base64) throws Exception {
        byte[] raw = Base64.getDecoder().decode(base64);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(raw))) {
            Object o = ois.readObject(); // ❌ unsafe: attacker-controlled serialized object
            return "Loaded: " + o.toString();
        }
    }
}
