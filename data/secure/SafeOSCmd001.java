package sample.secure;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/safe")
public class SafeOSCmd001 {

    // Secure counterpart: does NOT execute any OS command
    // Example: GET /safe/exec?cmd=whoami  -> returns a message instead of executing
    @GetMapping("/exec")
    public String exec(@RequestParam(required = false, defaultValue = "") String cmd) {
        // Reject dangerous usage and never pass user input to the OS
        if (!cmd.isEmpty()) {
            return "Command execution is disabled. Received: " + cmd.replaceAll("[^a-zA-Z0-9 _.-]", "");
        }
        return "OK";
    }
}
