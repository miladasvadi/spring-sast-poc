DATASET PLAN (Java/Spring) - plain text

Goal (first milestone)
- Build a small, clean dataset to prototype the ML stage:
  * ~400-600 total snippets (balanced): ~200 vulnerable + ~200 secure.
  * Cover at least the 10 CWEs below.
  * Each snippet: 20–120 LOC, self-contained, compilable in isolation.

Later goal
- >5000 total samples balanced across CWEs.

Candidate Sources (Java / Spring)
1) Vul4J — curated Java vulns with fixing commits.
2) Juliet/SARD (Java) — many labeled CWEs; baseline.
3) NVD / OSV — CVEs for `spring-framework`, `spring-boot` and commit diffs.
4) GitHub Advisory DB — links to CVEs and fixing commits.
5) OWASP WebGoat (Java) — intentional vulns (some Spring modules).
6) Synthetic sets (this repo):
   - data/vuln/         (hand‑crafted vulnerable)
   - data/secure/       (safe variants)
   - data/vuln_auto/    (auto‑generated from secure)

Spring filtering heuristics (keep files that “look” Spring)
- Imports like `org.springframework.*`
- Annotations: `@Controller`, `@RestController`, `@RequestMapping`, `@GetMapping`, `@PostMapping`
- Spring Boot hints: `@SpringBootApplication`, `application.properties`, `pom.xml`

CWE focus (current rules)
- CWE‑78  OS Command Injection
- CWE‑22  Path Traversal
- CWE‑601 Open Redirect
- CWE‑89  SQL Injection (JPA/JdbcTemplate)
- CWE‑918 SSRF
- CWE‑79  XSS
- CWE‑502 Insecure Deserialization
- CWE‑434 Unrestricted File Upload
- CWE‑352 CSRF
- CWE‑327 Weak Crypto

Minimal metadata per sample (JSON schema idea)
{
  "id": "SafeSQLi001",
  "label": "secure" | "vuln",
  "cwe": "CWE-89",
  "framework": ["spring-mvc"],
  "features": ["@Controller","JdbcTemplate"],
  "source": "synthetic|vul4j|nvd|webgoat",
  "path": "data/secure/SafeSQLi001.java",
  "license": "Apache-2.0|MIT|unknown"
}

Folder structure in this repo
data/
  secure/           # curated safe snippets
  vuln/             # hand-crafted vulnerable
  vuln_auto/        # auto-generated from secure
  real_world/
    spring_cve/     # mined CVE-based vulnerable snippets (to add)
dataset_index.json  # unified registry (extend with real_world entries)
docs/
  dataset_plan.md   # this document (markdown version)

Quality rules
- Each pair (vuln vs safe) differs minimally (showing only the risky pattern).
- Buildable Java files (class + package if needed), minimal imports.
- No personal data; keep licenses of copied sources.
- For CVE-based entries add: CVE id, repo, commit SHA (vuln and fix).

Next actions (short checklist)
[ ] Create `data/real_world/spring_cve/` (empty placeholder).
[ ] Add 20 CVE-based Spring snippets (first batch).
[ ] Extend `dataset_index.json` with these entries.
[ ] Write helper script to fetch/analyze CVE commit diffs.
