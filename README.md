# Spring SAST PoC (AST-based, Endpoint-Scoped)

یک PoC سبک برای تحلیل ایستای کدهای **Spring / Spring Boot**. ایده اینه که اول endpointها را پیدا کنیم و بعد داخل همان متدها (intra-procedural) به‌دنبال الگوهای آسیب‌پذیری بگردیم و خروجی استاندارد **SARIF** بدهیم.

## چه کار می‌کند؟
- **pre-pass**: کشف endpointهای Spring MVC و استخراج وابستگی‌ها
- **scan (endpoint-scoped)**: بررسی هر endpoint برای الگوهای ناامن
- خروجی‌ها: `JSON` و **`SARIF 2.1.0`** (قابل استفاده در *GitHub Code Scanning*)

### پوشش فعلی
- **CWE-78**: OS Command Injection (`Runtime.exec`, `ProcessBuilder`, …)
- **CWE-22**: Path Traversal (`new File(..)`, `Files.newInputStream(..)`, …)

---

## پیش‌نیاز
- **Python 3.10+**
- نصب وابستگی‌ها:
```bash
pip install -r requirements.txt
