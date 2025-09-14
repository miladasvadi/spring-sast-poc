package sample.vuln;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;

@RestController
public class VulnerableFileUpload001 {

    // VULN: ذخیره فایل با نام اصلی کاربر در مسیر قابل اجرا/وب
    @PostMapping("/upload")
    public String upload(@RequestParam("file") MultipartFile file) throws Exception {
        File dest = new File("C:/appdata/wwwroot/uploads/" + file.getOriginalFilename());
        file.transferTo(dest);
        return "Saved to: " + dest.getAbsolutePath();
    }
}
