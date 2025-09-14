package sample.secure;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import java.net.URI;

@RestController
public class SafeSSRF001 {

    private final RestTemplate rt = new RestTemplate();

    // SAFE: allow only http(s) and a small allowlist of hosts
    private boolean isAllowed(URI u) {
        if (u == null) return false;
        String scheme = u.getScheme();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) return false;
        String host = u.getHost();
        return host != null && (host.equalsIgnoreCase("example.com") || host.equalsIgnoreCase("api.example.com"));
    }

    @GetMapping("/fetch-safe")
    public String fetchSafe(@RequestParam String url) throws Exception {
        URI u = new URI(url);
        if (!isAllowed(u)) return "Blocked: URL not allowed";
        return rt.getForObject(u, String.class);
    }
}
