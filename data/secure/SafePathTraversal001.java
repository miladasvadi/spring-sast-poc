package sample.secure;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;

@RestController
public class SafePathTraversal001 {

    // SAFE: restrict to a fixed base directory and validate canonical path
    private static final Path BASE = Paths.get("C:/appdata/uploads").toAbsolutePath().normalize();

    @GetMapping("/read-safe")
    public String read(@RequestParam String path) throws Exception {
        Path requested = Paths.get(path).normalize();
        Path resolved = BASE.resolve(requested).normalize();
        if (!resolved.startsWith(BASE)) {
            return "Blocked: invalid path";
        }
        if (!Files.exists(resolved) || !Files.isRegularFile(resolved)) {
            return "File not found";
        }
        byte[] bytes = Files.readAllBytes(resolved);
        return new String(bytes);
    }
}
