# Spring SAST PoC (AST-based, Endpoint-Scoped)

یک PoC سبک برای تحلیل ایستای کدهای **Spring / Spring Boot**:
- مرحله‌ی **pre-pass**: کشف اندپوینت‌ها و وابستگی‌ها
- **اسکن endpoint-scoped (intra-procedural)**: پیدا کردن الگوهای آسیب‌پذیری در همان متد
- خروجی‌های استاندارد: **JSON** و **SARIF 2.1.0**

پوشش فعلی:
- **CWE-78**: OS Command Injection (`Runtime.exec`, `ProcessBuilder`, …)
- **CWE-22**: Path Traversal (`new File(..)`, `Files.newInputStream(..)`, …)

## نصب سریع
> Python 3.10+ لازم است.

```bash
pip install -r requirements.txt
