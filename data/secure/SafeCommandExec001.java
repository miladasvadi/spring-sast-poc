package sample.secure;

import org.springframework.web.bind.annotation.*;
import java.util.Set;

@RestController
public class SafeCommandExec001 {

    // SAFE: whitelist fixed commands; no raw user-controlled exec
    private static final Set<String> ALLOWED = Set.of("date", "whoami");

    @GetMapping("/exec-safe")
    public String execSafe(@RequestParam String cmd) throws Exception {
        if (!ALLOWED.contains(cmd)) {
            return "Blocked: command not allowed";
        }
        Process p = new ProcessBuilder(cmd).start();
        p.waitFor();
        return "Executed safe command: " + cmd;
    }
}
