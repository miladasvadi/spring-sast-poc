package sample.vuln;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
public class VulnerableSSRF001 {

    private final RestTemplate rt = new RestTemplate();

    // VULN: fetches arbitrary URL from user input (SSRF)
    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) {
        return rt.getForObject(url, String.class);
    }
}
