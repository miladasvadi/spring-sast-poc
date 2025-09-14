package sample.vuln;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.nio.file.Files;

@RestController
public class VulnerablePathTraversal001 {

    // VULN: Path Traversal via unvalidated 'path' parameter
    // Example (DON'T run): GET /read?path=../../windows/win.ini
    @GetMapping("/read")
    public String read(@RequestParam String path) throws Exception {
        File f = new File(path);                 // no validation / normalization
        byte[] bytes = Files.readAllBytes(f.toPath()); // may read arbitrary files
        return new String(bytes);
    }
}
