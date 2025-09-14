package sample.secure;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.UUID;

@RestController
public class SafeFileUpload001 {

    private static final Set<String> ALLOWED = Set.of("png","jpg","jpeg","pdf");
    private static final Path BASE = Path.of("C:/appdata/safe-uploads").toAbsolutePath().normalize();

    // SAFE: اعتبارسنجی پسوند و نام‌گذاری تصادفی در مسیری خارج از وب‌روت
    @PostMapping("/upload-safe")
    public String uploadSafe(@RequestParam("file") MultipartFile file) throws Exception {
        if (file.isEmpty()) return "No file";
        String name = file.getOriginalFilename();
        String ext = (name != null && name.contains(".")) ? name.substring(name.lastIndexOf('.')+1).toLowerCase() : "";
        if (!ALLOWED.contains(ext)) return "Blocked: extension not allowed";

        Files.createDirectories(BASE);
        String randomName = UUID.randomUUID().toString() + "." + ext;
        Path dest = BASE.resolve(randomName).normalize();
        if (!dest.startsWith(BASE)) return "Blocked: invalid path";
        file.transferTo(dest.toFile());
        return "Saved (safe) to: " + dest.toString();
    }
}
