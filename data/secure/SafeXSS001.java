package sample.secure;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.MediaType;
import org.springframework.web.util.HtmlUtils;

@RestController
public class SafeXSS001 {

    // SAFE: escape ورودی کاربر قبل از رندر HTML
    @GetMapping(value = "/echo-safe", produces = MediaType.TEXT_HTML_VALUE)
    public String echoSafe(@RequestParam String q) {
        String safe = HtmlUtils.htmlEscape(q);
        return "<h1>Echo:</h1>" + safe;
    }
}
