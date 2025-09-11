# -*- coding: utf-8 -*-
"""
scan_intraprocedural.py  (v1.2 hotfix)
- سقف عمق پیمایش AST برای جلوگیری از گیر کردن
- لاگ مرحله‌ای در حالت --debug
- Sanitizer ساده برای CWE-22 (مثل قبل)

pip install javalang
"""
import os, sys, json, argparse, traceback, time
from pathlib import Path
import javalang
import re

VER = "1.2"
OS_CMD_RE   = re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(', re.MULTILINE)
PATH_TRAV_RE= re.compile(r'new\s+[A-Za-z0-9_$.]*FileInputStream\s*\(|\bFiles\.(?:newInputStream|newBufferedReader|readAllLines)\s*\(|\bPaths\.get\s*\(', re.MULTILINE)
ENABLE_REGEX_FALLBACK = False
TIME_BUDGET_PER_METHOD = 5.0     # حداکثر 5 ثانیه به ازای هر متد
MAX_CALLS_PER_METHOD   = 500     # حداکثر 500 فراخوانی (MethodInvocation/ClassCreator) در هر متد

# محدودکننده‌ی عمق پیمایش
MAX_AST_WALK_DEPTH = 40

RULES = [
    {
        "id": "JAVA-CWE-78-OSCommand",
        "name": "OS Command Injection via Runtime/ProcessBuilder",
        "severity": "error",
        "cwe": "CWE-78",
        "helpUri": "https://cwe.mitre.org/data/definitions/78.html",
        "sinks": {
            "method_names": ["exec", "start"],
            "classes_any": ["Runtime", "ProcessBuilder"]
        },
        "sanitizers": []
    },
    {
        "id": "JAVA-CWE-89-SQLi",
        "name": "SQL Injection via Statement/EntityManager",
        "severity": "error",
        "cwe": "CWE-89",
        "helpUri": "https://cwe.mitre.org/data/definitions/89.html",
        "sinks": {
            "method_names": ["execute", "executeQuery", "executeUpdate", "createNativeQuery", "prepareStatement"],
            "classes_any": ["Statement", "PreparedStatement", "EntityManager"]
        },
        "sanitizers": []
    },
    {
        "id": "JAVA-CWE-22-PathTraversal",
        "name": "Path Traversal via File/Paths/Files",
        "severity": "warning",
        "cwe": "CWE-22",
        "helpUri": "https://cwe.mitre.org/data/definitions/22.html",
        "sinks": {
            "method_names": ["get", "newInputStream", "newBufferedReader", "readAllLines"],
            "classes_any": ["Paths", "Files", "File", "FileInputStream", "FileOutputStream"]
        },
        "sanitizers": [
            "cleanPath", "normalize", "getCanonicalPath", "getName"
        ]
    },
]

def load_endpoints(endpoints_json):
    if not endpoints_json:
        return set(), {}
    with open(endpoints_json, "r", encoding="utf-8") as f:
        eps = json.load(f)
    keys = set()
    files = set()
    for e in eps:
        k = (os.path.normpath(e["file"]).lower(), e["class"], e["method"])
        keys.add(k)
        files.add(os.path.normpath(e["file"]).lower())
    return keys, {"files": files, "exact": keys, "raw": eps}

def read_java_files(project_root):
    out = []
    for root, _, files in os.walk(project_root):
        for fn in files:
            if fn.endswith(".java"):
                out.append(os.path.join(root, fn))
    return out

# ---- پیمایش‌های امن با سقف عمق ----
def expr_uses_names(node, names: set, depth=0):
    if node is None or depth > MAX_AST_WALK_DEPTH:
        return False
    try:
        if hasattr(node, "member") and isinstance(node.member, str) and node.member in names:
            return True
        if hasattr(node, "qualifier") and isinstance(node.qualifier, str) and node.qualifier in names:
            return True
        if hasattr(node, "name") and isinstance(node.name, str) and node.name in names:
            return True
        if isinstance(node, javalang.tree.MemberReference):
            if getattr(node, "member", None) in names:
                return True
        for _, child in node:
            if expr_uses_names(child, names, depth+1):
                return True
    except Exception:
        pass
    return False

def expr_has_sanitizer_member(node, sanitizer_members: set, depth=0):
    if node is None or not sanitizer_members or depth > MAX_AST_WALK_DEPTH:
        return False
    try:
        for _, child in node:
            if isinstance(child, javalang.tree.MethodInvocation):
                m = getattr(child, "member", None)
                if isinstance(m, str) and m in sanitizer_members:
                    return True
            if expr_has_sanitizer_member(child, sanitizer_members, depth+1):
                return True
    except Exception:
        pass
    return False

def collect_taint_and_sanitize(method_decl, debug=False):
    """
    تِینت/سَنیتایز سریع و پایدار:
    - پارامترها تِینت فرض می‌شوند.
    - LocalVariableDeclaration و Assignment را با filter می‌خوانیم (بدون DFS سنگین).
    - اگر در initializer متدهای sanitize باشد، متغیر sanitized می‌شود.
    """
    tainted   = set(p.name for p in (method_decl.parameters or []) if getattr(p, "name", None))
    sanitized = set()

    # لیست متدهای sanitizer برای CWE-22
    path_rule = next((r for r in RULES if r["id"].endswith("CWE-22-PathTraversal")), None)
    sanitizer_members = set(path_rule["sanitizers"]) if path_rule else set()

    # Helperها
    def _uses_taint(node):
        return expr_uses_names(node, tainted, 0)

    def _has_sanit(node):
        return sanitizer_members and expr_has_sanitizer_member(node, sanitizer_members, 0)

    # 1) varهای لوکال:  String c = <expr>;
    for _, decl in method_decl.filter(javalang.tree.LocalVariableDeclaration):
        for d in getattr(decl, "declarators", []) or []:
            init = getattr(d, "initializer", None)
            if init is None or not getattr(d, "name", None):
                continue
            if _uses_taint(init):
                # اگر داخل expr سَنیتایزر بود → sanitized؛ وگرنه tainted
                if _has_sanit(init):
                    sanitized.add(d.name)
                else:
                    tainted.add(d.name)

    # 2) انتساب‌ها:  c = <expr>;
    for _, asn in method_decl.filter(javalang.tree.Assignment):
        lhs = getattr(asn, "expressionl", None) or getattr(asn, "lvalue", None) or getattr(asn, "left", None)
        rhs = getattr(asn, "value", None)        or getattr(asn, "rvalue", None) or getattr(asn, "right", None)
        if rhs is None or lhs is None:
            continue
        if _uses_taint(rhs) and not _has_sanit(rhs):
            lhs_name = getattr(lhs, "member", None) or getattr(lhs, "name", None)
            if isinstance(lhs_name, str):
                tainted.add(lhs_name)

    return tainted, sanitized







def expr_uses_tainted(node, tainted_names):
    if node is None:
        return False

    # چک فیلدهای متداولِ ارجاع به نام
    if hasattr(node, "member") and isinstance(node.member, str) and node.member in tainted_names:
        return True
    if hasattr(node, "qualifier") and isinstance(node.qualifier, str) and node.qualifier in tainted_names:
        return True
    if hasattr(node, "name") and isinstance(node.name, str) and node.name in tainted_names:
        return True

    # پیمایش امنِ فرزندان
    try:
        for _, child in node:
            if expr_uses_tainted(child, tainted_names):
                return True
    except Exception:
        pass
    return False

def collect_tainted(method_decl):
    tainted = set()

    # پارامترهای متد را آلوده فرض می‌کنیم
    for p in getattr(method_decl, "parameters", []) or []:
        if getattr(p, "name", None):
            tainted.add(p.name)

    # انتشار آلودگی در لوکال‌ها و انتساب‌ها
    def visit(node):
        for _, ch in node:
            cname = type(ch).__name__

            # int x = <expr>;  اگر expr آلوده باشد، x آلوده می‌شود
            if cname == "LocalVariableDeclaration":
                for d in getattr(ch, "declarators", []) or []:
                    init = getattr(d, "initializer", None)
                    if init is not None and expr_uses_tainted(init, tainted):
                        if getattr(d, "name", None):
                            tainted.add(d.name)

            # x = <expr>;     تلاش مینیمال برای Assignment
            elif cname == "Assignment":
                lhs = getattr(ch, "expressionl", None) or getattr(ch, "lvalue", None) or getattr(ch, "left", None)
                rhs = getattr(ch, "value", None)        or getattr(ch, "rvalue", None) or getattr(ch, "right", None)
                if rhs is not None and expr_uses_tainted(rhs, tainted):
                    lhs_name = getattr(lhs, "member", None) or getattr(lhs, "name", None)
                    if isinstance(lhs_name, str):
                        tainted.add(lhs_name)

            if hasattr(ch, "children"):
                visit(ch)

    if getattr(method_decl, "body", None):
        for stmt in method_decl.body:
            visit(stmt)

    return tainted


def call_matches_rule(call_node, rule):
    """
    Match منطقی برای MethodInvocation:
    - اسم متد باید در rule باشد.
    - اگر کلاس مشخص شده، یا باید qualifier بخورد (Files/Paths/...) یا استاتیک ایمپورت باشد (بدون qualifier).
    - برای get نیازی نیست حتماً 'Paths' دیده شود؛ چون ممکن است static import شده باشد.
    """
    mname = getattr(call_node, "member", None) or getattr(call_node, "name", None)
    if mname not in rule["sinks"]["method_names"]:
        return False

    classes = set(rule["sinks"]["classes_any"])
    qualifiers = set()

    q = getattr(call_node, "qualifier", None)
    if isinstance(q, str) and q:
        qualifiers.add(q.split(".")[-1])

    sel = getattr(call_node, "select", None)
    if sel and hasattr(sel, "type") and hasattr(sel.type, "name"):
        qualifiers.add(sel.type.name.split(".")[-1])

    if classes:
        # اگر استاتیک ایمپورت شده (qualifier ندارد) هم اجازه بده
        return (not qualifiers) or bool(qualifiers & classes)

    return True






def detect_sinks_in_method(method_decl, file_path, class_name, endpoints_keyset=None, debug=False):
    """
    نسخه‌ی سریع و پایدار:
    - محدود به اندپوینت‌ها
    - بررسی MethodInvocation/ClassCreator
    - بودجه‌ی زمانی و سقف شمارنده برای جلوگیری از گیر کردن
    - کش برای expr_uses_names / expr_has_sanitizer_member
    - fallback شماره‌ی خط: اگر نود position نداشت، از خط شروع متد استفاده می‌کنیم
    """
    # فقط متدهای اندپوینت را اسکن کن (اگر scope داده شده)
    if endpoints_keyset:
        k = (os.path.normpath(file_path).lower(), class_name, method_decl.name)
        if k not in endpoints_keyset:
            return []

    start_ts = time.perf_counter()
    findings = []
    found_rule_in_this_method, seen_keys = set(), set()

    # taint + sanitized
    tainted, sanitized = collect_taint_and_sanitize(method_decl, debug=debug)
    param_names = {p.name for p in (method_decl.parameters or []) if getattr(p, "name", None)}

    # کش‌های سبک
    cache_taint = {}
    cache_san = {}
    cache_has_sanit = {}

    def uses_names_cached(node, names, cache):
        key = (id(node), id(names))
        v = cache.get(key)
        if v is None:
            v = expr_uses_names(node, names, 0)
            cache[key] = v
        return v

    def has_sanitizer_cached(node, members):
        if not members:
            return False
        key = (id(node), tuple(sorted(members)))
        v = cache_has_sanit.get(key)
        if v is None:
            v = expr_has_sanitizer_member(node, members, 0)
            cache_has_sanit[key] = v
        return v

    def add_finding(rule, line, call_display):
        if rule["id"] in found_rule_in_this_method:
            return
        key = (rule["id"], file_path, class_name, method_decl.name, line or 1, call_display)
        if key in seen_keys:
            return
        seen_keys.add(key)
        found_rule_in_this_method.add(rule["id"])
        findings.append({
            "ruleId":   rule["id"],
            "ruleName": rule["name"],
            "severity": rule["severity"],
            "cwe":      rule.get("cwe"),
            "helpUri":  rule.get("helpUri"),
            "file":     file_path,
            "class":    class_name,
            "method":   method_decl.name,
            "line":     line or 1,
            "message":  f"Potential {rule['name']} at {call_display}",
        })

    def arg_is_effectively_tainted(arg, rule):
        # شورت‌کات: ارجاع مستقیم به پارامتر
        if isinstance(arg, javalang.tree.MemberReference) and getattr(arg, "member", None) in param_names:
            direct_taint = True
        else:
            direct_taint = uses_names_cached(arg, tainted, cache_taint)

        if not direct_taint:
            return False
        if uses_names_cached(arg, sanitized, cache_san):
            return False
        sanitizer_members = set(rule.get("sanitizers") or [])
        if sanitizer_members and has_sanitizer_cached(arg, sanitizer_members):
            return False
        return True

    # شمارنده‌ی فراخوانی‌ها + بودجه‌ی زمانی
    calls_scanned = 0

    # --- MethodInvocation (مثل Runtime.getRuntime().exec(cmd))
    for _, inv in method_decl.filter(javalang.tree.MethodInvocation):
        if calls_scanned >= MAX_CALLS_PER_METHOD or (time.perf_counter() - start_ts) > TIME_BUDGET_PER_METHOD:
            if debug:
                print(f"[DBG] timeout/cap {file_path}::{class_name}.{method_decl.name} (invocations)")
            break
        calls_scanned += 1

        for rule in RULES:
            if call_matches_rule(inv, rule):
                args = getattr(inv, "arguments", []) or []
                # بودجه‌ی زمانی درون حلقه
                if (time.perf_counter() - start_ts) > TIME_BUDGET_PER_METHOD:
                    break
                if any(arg_is_effectively_tainted(a, rule) for a in args):
                    pos = getattr(inv, "position", None)
                    line = (pos.line if pos else
                            (getattr(method_decl, "position", None).line if getattr(method_decl, "position", None) else 1))
                    mname = getattr(inv, "member", None) or getattr(inv, "name", None) or "call"
                    add_finding(rule, line, f"call `{mname}`")

    # --- ClassCreator (مثل new FileInputStream(path))
    for _, cc in method_decl.filter(javalang.tree.ClassCreator):
        if calls_scanned >= MAX_CALLS_PER_METHOD or (time.perf_counter() - start_ts) > TIME_BUDGET_PER_METHOD:
            if debug:
                print(f"[DBG] timeout/cap {file_path}::{class_name}.{method_decl.name} (constructors)")
            break
        calls_scanned += 1

        typ = getattr(cc, "type", None)
        tname = (getattr(typ, "name", None) or "")
        short = tname.split(".")[-1] if tname else ""
        if not short:
            continue

        args = getattr(cc, "arguments", []) or []
        for rule in RULES:
            if short in rule["sinks"]["classes_any"]:
                if (time.perf_counter() - start_ts) > TIME_BUDGET_PER_METHOD:
                    break
                if any(arg_is_effectively_tainted(a, rule) for a in args):
                    pos = getattr(cc, "position", None)
                    line = (pos.line if pos else
                            (getattr(method_decl, "position", None).line if getattr(method_decl, "position", None) else 1))
                    add_finding(rule, line, f"constructor `{short}(...)`")

    return findings








def scan_file_ast(jf, endpoints_keyset, endpoints_meta=None, debug=False):
    t0 = time.perf_counter()
    if debug: print(f"[DBG] Parsing: {jf}")
    try:
        with open(jf, "r", encoding="utf-8") as f:
            src = f.read()
        tree = javalang.parse.parse(src)
    except Exception as e:
        if debug: print(f"[DBG] Parse-fail: {jf} ({e})")
        return []
    t1 = time.perf_counter()
    if debug: print(f"[DBG] Detect  : {jf}")
    all_findings = []
    for t in getattr(tree, "types", []) or []:
        if not hasattr(t, "name"):
            continue
        class_name = t.name
        for m in getattr(t, "methods", []) or []:
            try:
                all_findings.extend(
                    detect_sinks_in_method(m, jf, class_name, endpoints_keyset, debug=debug)
                )
            except Exception as e:
                if debug: print(f"[DBG] detect fail {jf}::{class_name}.{getattr(m,'name', '?')}: {e}")
    t2 = time.perf_counter()
    if debug: print(f"[DBG] Done    : {jf} → findings={len(all_findings)} (parse {t1-t0:.3f}s, detect {t2-t1:.3f}s)")
    return all_findings

def _build_method_index_for_file(src_text):
    # لیست [(start_line, class_name, method_name)]
    index = []
    try:
        tree = javalang.parse.parse(src_text)
    except:
        return index
    for t in getattr(tree, "types", []) or []:
        cname = getattr(t, "name", None)
        for m in getattr(t, "methods", []) or []:
            pos = getattr(m, "position", None)
            if pos and pos.line:
                index.append((pos.line, cname, m.name))
    index.sort(key=lambda x: x[0])
    return index

def _owner_by_line(method_index, line):
    # نزدیک‌ترین متدی که شروعش <= line
    owner = (None, None)
    for (start, cls, mth) in method_index:
        if start <= line:
            owner = (cls, mth)
        else:
            break
    return owner


def regex_scan_file(jf, endpoints_meta):
    if not ENABLE_REGEX_FALLBACK:
        return []
    if endpoints_meta and endpoints_meta.get("files"):
        if os.path.normpath(jf).lower() not in endpoints_meta["files"]:
            return []

    try:
        with open(jf, "r", encoding="utf-8") as f:
            src = f.read()
    except Exception:
        return []

    # برای نسبت‌دادن خطوط regex به نزدیک‌ترین متد/کلاس
    method_index = _build_method_index_for_file(src)

    findings = []

    def add(rule, line, msg):
        cls, mth = _owner_by_line(method_index, line)
        findings.append({
            "ruleId":   rule["id"],
            "ruleName": rule["name"],
            "severity": rule["severity"],
            "cwe":      rule.get("cwe"),
            "helpUri":  rule.get("helpUri"),
            "file":     jf,
            "class":    cls,
            "method":   mth,
            "line":     line or 1,
            "message":  msg,
        })

    # OS Command
    for m in OS_CMD_RE.finditer(src):
        line = src.count("\n", 0, m.start()) + 1
        rule = next(r for r in RULES if r["id"] == "JAVA-CWE-78-OSCommand")
        add(rule, line, "Potential OS Command Injection (regex fallback)")

    # Path Traversal
    for m in PATH_TRAV_RE.finditer(src):
        line = src.count("\n", 0, m.start()) + 1
        rule = next(r for r in RULES if r["id"] == "JAVA-CWE-22-PathTraversal")
        add(rule, line, "Potential Path Traversal (regex fallback)")

    return findings




def scan_project(project_root, endpoints_json, debug=False):
    endpoints_keyset, endpoints_meta = load_endpoints(endpoints_json)
    java_files = read_java_files(project_root)

    if debug:
        print(f"[DBG] endpoints: exact={len(endpoints_keyset)}, files={len(endpoints_meta.get('files', [])) if endpoints_meta else 0}")
        for s in list(endpoints_keyset)[:5]:
            print("  [DBG] sample:", s)

    all_findings = []
    print(f"[INFO] Scanning (endpoint-scoped): {project_root}")
    for jf in java_files:
        # اگر endpoint-scoping داریم، فقط فایل‌های مربوط به اندپوینت‌ها را بررسی کن
        if endpoints_meta and endpoints_meta.get("files"):
            if os.path.normpath(jf).lower() not in endpoints_meta["files"]:
                continue

        # 1) AST
        f_ast = scan_file_ast(jf, endpoints_keyset, endpoints_meta, debug=debug)
        # 2) regex fallback
        f_rx  = regex_scan_file(jf, endpoints_meta)

        # --- dedupe: روی (ruleId, file, line) کلید می‌کنیم و اگر همون کلید
        #     هم AST و هم regex داشت، AST (class != None) را نگه می‌داریم.
        by_key = {}
        for f in (f_ast + f_rx):
            k = (f["ruleId"], f["file"], f["line"])
            old = by_key.get(k)
            if old is None or (old.get("class") is None and f.get("class") is not None):
                by_key[k] = f

        merged = list(by_key.values())
        all_findings.extend(merged)

    return all_findings



def write_sarif(findings, outdir):
    sarif = to_sarif(findings)
    out = os.path.join(outdir, "findings.sarif")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    return out

def write_json(findings, outdir):
    out = os.path.join(outdir, "findings.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    return out

def to_sarif(findings):
    # قوانین یکتا
    rules = {}
    for f in findings:
        rid = f.get("ruleId")
        if not rid:
            continue
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.get("ruleName", rid),
                "shortDescription": {"text": f.get("ruleName", rid)},
                "helpUri": f.get("helpUri"),
                "properties": {"cwe": f.get("cwe")},
                "defaultConfiguration": {"level": f.get("severity", "warning")},
            }

    # نتایج
    results = []
    for f in findings:
        file_uri = Path(f["file"]).as_posix()
        start_line = int(f.get("line", 1)) if str(f.get("line", "")).isdigit() else 1
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": file_uri},
                "region": {"startLine": start_line}
            }
        }
        results.append({
            "ruleId": f["ruleId"],
            "level": f.get("severity", "warning"),
            "message": {"text": f.get("message", "")},
            "locations": [{"location": loc}],
        })

    return {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SpringSAST-POC",
                    "informationUri": "https://example.com",
                    "version": VER,
                    "rules": list(rules.values()),
                }
            },
            "results": results
        }]
    }


def main():
    ap = argparse.ArgumentParser(description=f"Intra-procedural scan for Spring endpoints (PoC) v{VER}")
    ap.add_argument("--project", required=True, help="مسیر پروژه جاوا")
    ap.add_argument("--endpoints", required=False, default=None, help="(اختیاری) spring_endpoints.json")
    ap.add_argument("--outdir", required=False, default=".", help="مسیر خروجی")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    project = os.path.normpath(args.project)
    endpoints = os.path.normpath(args.endpoints) if args.endpoints else None
    outdir = os.path.normpath(args.outdir)
    os.makedirs(outdir, exist_ok=True)

    if args.debug:
        print(f"[VER] scan_intraprocedural VER={VER}")

    findings = scan_project(project, endpoints, debug=args.debug)

    jf = write_json(findings, outdir)
    sf = write_sarif(findings, outdir)

    print(f"[OK] Findings written:")
    print(f"  - JSON : {jf}")
    print(f"  - SARIF: {sf}")
    print(f"[STATS] Total findings: {len(findings)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted.")
    except Exception:
        traceback.print_exc()
        sys.exit(1)
