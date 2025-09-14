package sample.vuln;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.InputStreamReader;

@RestController
@RequestMapping("/vuln")
public class VulnOSCmd001 {

    // CWE-78: OS Command Injection (INTENTIONAL VULNERABILITY FOR DATASET)
    // Example: GET /vuln/exec?cmd=whoami
    @GetMapping("/exec")
    public String exec(@RequestParam String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(cmd); // vulnerable sink
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = r.readLine()) != null) {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }
}
