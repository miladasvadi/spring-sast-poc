package sample.vuln;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class VulnerableCommandExec001 {

    // VULN: unsafely passes user input to OS command
    // Example (DON'T run): /exec?cmd=calc.exe  (Windows)  or  /exec?cmd=touch /tmp/pwn
    @GetMapping("/exec")
    public String exec(@RequestParam String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(cmd);
        p.waitFor();
        return "Executed: " + cmd;
    }
}
