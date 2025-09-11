# -*- coding: utf-8 -*-
r"""
prepass_spring.py
- کشف endpointها از روی @RequestMapping/@GetMapping/... (با AST اگر javalang باشد، وگرنه regex)
- ترکیب base path کلاس با path متد و استخراج HTTP method/consumes/produces
- استخراج dependencyها از pom.xml
- خروجی JSON در Desktop/temp: spring_endpoints.json , spring_deps.json

Usage (Windows):
  python "C:/Users/milad/Desktop/temp/prepass_spring.py" --project-root "C:/Users/milad/Desktop/temp/demo-spring" --out-dir "C:/Users/milad/Desktop/temp"
"""

from __future__ import annotations
import os
import re
import json
import argparse
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional, Tuple

try:
    import javalang
    HAVE_JAVALANG = True
except Exception:
    HAVE_JAVALANG = False

def get_desktop_temp_dir() -> str:
    base = os.path.expanduser("~")
    d = os.path.join(base, "Desktop", "temp")
    os.makedirs(d, exist_ok=True)
    return d

def write_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def normalize_path_join(base_path: str, sub_path: str) -> str:
    def _clean(s: str) -> str:
        s = (s or "").strip().strip('"').strip("'").replace("\\", "/")
        while '//' in s:
            s = s.replace('//', '/')
        return s
    base = _clean(base_path)
    sub  = _clean(sub_path)
    if not base and not sub:
        return "/"
    if base and not base.startswith("/"):
        base = "/" + base
    if sub and sub.startswith("/"):
        sub = sub[1:]
    out = (f"{base}/{sub}" if sub else base) or "/"
    while '//' in out:
        out = out.replace('//', '/')
    return out or "/"

def iter_java_files(root: str) -> List[str]:
    javas = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fn.endswith(".java"):
                javas.append(os.path.join(dirpath, fn))
    return javas

def safe_read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(path, "r", encoding="latin-1", errors="ignore") as f:
            return f.read()

def find_pom_xml(root: str) -> Optional[str]:
    cand = os.path.join(root, "pom.xml")
    if os.path.isfile(cand):
        return cand
    for dirpath, _, filenames in os.walk(root):
        if "pom.xml" in filenames:
            return os.path.join(dirpath, "pom.xml")
    return None

def _get_text(elem, ns=None, tag=None) -> str:
    if elem is None:
        return ""
    if tag is None:
        return (elem.text or "").strip()
    if ns:
        e = elem.find(f"m:{tag}", ns)
    else:
        e = elem.find(tag)
    return (e.text or "").strip() if e is not None else ""

def parse_pom_dependencies(pom_path: str) -> List[Dict[str, str]]:
    deps = []
    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()
        ns = {"m": root.tag.split('}')[0].strip('{')} if '}' in root.tag else None
        if ns:
            dep_sets = root.findall(".//m:dependencies", ns)
        else:
            dep_sets = root.findall(".//dependencies")
        for deps_tag in dep_sets:
            dep_nodes = deps_tag.findall("m:dependency", ns) if ns else deps_tag.findall("dependency")
            for dep in dep_nodes:
                deps.append({
                    "groupId":    _get_text(dep, ns, "groupId"),
                    "artifactId": _get_text(dep, ns, "artifactId"),
                    "version":    _get_text(dep, ns, "version"),
                    "scope":      _get_text(dep, ns, "scope"),
                })
    except Exception as e:
        print(f"[WARN] parse_pom_dependencies error: {e}")
    return deps

MAPPING_ANN = {
    "RequestMapping": None,
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
}

def _extract_str_values(val) -> List[str]:
    from javalang.tree import Literal, MemberReference, ArrayInitializer
    outs = []
    if isinstance(val, str):
        outs.append(val.strip('"').strip("'"))
    elif hasattr(val, 'value') and isinstance(val, Literal):
        if isinstance(val.value, str):
            outs.append(val.value.strip('"').strip("'"))
    elif isinstance(val, ArrayInitializer):
        for it in val.initializers or []:
            if hasattr(it, 'value') and isinstance(it.value, str):
                outs.append(it.value.strip('"').strip("'"))
    elif isinstance(val, MemberReference):
        if val.member:
            outs.append(val.member)
    return [s for s in outs if s is not None]

def _extract_request_methods(val) -> List[str]:
    from javalang.tree import MemberReference, ArrayInitializer
    methods = []
    if isinstance(val, MemberReference):
        if val.member:
            methods.append(val.member.upper())
    elif isinstance(val, ArrayInitializer):
        for it in val.initializers or []:
            if hasattr(it, "member") and it.member:
                methods.append(it.member.upper())
    return methods

def extract_endpoints_ast(java_path: str, text: str) -> List[Dict[str, Any]]:
    endpoints = []
    try:
        tree = javalang.parse.parse(text)
    except Exception:
        return endpoints

    for type_decl in getattr(tree, "types", []) or []:
        class_name = getattr(type_decl, "name", None)
        anns = getattr(type_decl, "annotations", []) or []
        class_anns = {a.name.split(".")[-1]: a for a in anns}
        is_controller = ("RestController" in class_anns) or ("Controller" in class_anns)

        base_path_vals: List[str] = []
        if "RequestMapping" in class_anns:
            ann = class_anns["RequestMapping"]
            elts = []
            if getattr(ann, "element_pairs", None):
                elts = ann.element_pairs
            elif getattr(ann, "element", None):
                elts = [ann.element] if not isinstance(ann.element, list) else ann.element
            for pair in elts or []:
                name = getattr(pair, "name", "")
                if name in ("value", "path"):
                    base_path_vals.extend(_extract_str_values(pair.value))

        for method in getattr(type_decl, "methods", []) or []:
            m_name = getattr(method, "name", None)
            m_pos = getattr(method, "position", None)
            m_line = m_pos.line if m_pos else None

            m_anns = {a.name.split(".")[-1]: a for a in (method.annotations or [])}
            matched, http_method = None, None
            path_vals: List[str] = []
            consumes: List[str] = []
            produces: List[str] = []

            for ann_name, http in MAPPING_ANN.items():
                if ann_name in m_anns:
                    matched = m_anns[ann_name]
                    http_method = http
                    break
            if not matched:
                continue

            elts = []
            if getattr(matched, "element_pairs", None):
                elts = matched.element_pairs
            elif getattr(matched, "element", None):
                elts = [matched.element] if not isinstance(matched.element, list) else matched.element

            for pair in elts or []:
                name = getattr(pair, "name", "")
                if name in ("value", "path"):
                    path_vals.extend(_extract_str_values(pair.value))
                elif name == "consumes":
                    consumes.extend(_extract_str_values(pair.value))
                elif name == "produces":
                    produces.extend(_extract_str_values(pair.value))
                elif name == "method" and http_method is None:
                    rms = _extract_request_methods(pair.value)
                    if rms:
                        http_method = "|".join(rms)

            if not path_vals:
                path_vals = [""]

            base_vals = base_path_vals or [""]
            http_methods = [http_method] if (http_method and "|" not in http_method) else (
                (http_method.split("|") if http_method else [None])
            )

            for b in base_vals:
                for p in path_vals:
                    full_path = normalize_path_join(b, p)
                    for hm in http_methods:
                        endpoints.append({
                            "file": java_path.replace("\\", "/"),
                            "class": class_name,
                            "method": m_name,
                            "line": m_line,
                            "http_method": (hm or "UNKNOWN"),
                            "path": full_path,
                            "consumes": consumes or [],
                            "produces": produces or [],
                            "controller": bool(is_controller),
                            "detected_by": "ast",
                        })
    return endpoints

ANN_RE = re.compile(r"@(?P<ann>(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping))\s*(\((?P<args>[^)]*)\))?", re.MULTILINE)
CLASS_ANN_REST = re.compile(r"@(RestController|Controller)\b")
CLASS_DECL_RE = re.compile(r"\bclass\s+(?P<name>\w+)\b")
METHOD_DECL_RE = re.compile(r"(public|private|protected)\s+[<>\w\[\]]+\s+(?P<mname>\w+)\s*\(", re.MULTILINE)

def parse_args_kv(arg_str: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    if not arg_str:
        return out
    parts = [p.strip() for p in arg_str.split(",") if "=" in p]
    for pair in parts:
        k, v = pair.split("=", 1)
        k = k.strip()
        v = v.strip()
        vals: List[str] = []
        if v.startswith("{") and v.endswith("}"):
            inner = v[1:-1].strip()
            if inner:
                for it in [x.strip() for x in inner.split(",")]:
                    vals.append(it.strip('"').strip("'"))
        else:
            if v.startswith("RequestMethod."):
                vals.append(v.split(".", 1)[-1].strip().upper())
            else:
                vals.append(v.strip('"').strip("'"))
        out[k] = vals
    return out

def extract_endpoints_regex(java_path: str, text: str) -> List[Dict[str, Any]]:
    endpoints = []
    class_match = CLASS_DECL_RE.search(text)
    class_name = class_match.group("name") if class_match else None
    is_controller = bool(CLASS_ANN_REST.search(text))

    base_path_vals: List[str] = []
    for m in ANN_RE.finditer(text[: min(3000, len(text))]):
        if m.group("ann") == "RequestMapping":
            kvs = parse_args_kv(m.group("args") or "")
            b = kvs.get("value") or kvs.get("path") or []
            if b:
                base_path_vals = b
            break

    for m in ANN_RE.finditer(text):
        ann = m.group("ann")
        args = m.group("args") or ""
        kvs = parse_args_kv(args)
        http_method = None
        if ann in MAPPING_ANN and MAPPING_ANN[ann]:
            http_method = MAPPING_ANN[ann]
        elif ann == "RequestMapping":
            meths = kvs.get("method", [])
            if meths:
                http_method = "|".join(meths)

        paths = (kvs.get("value") or kvs.get("path") or [""])
        consumes = kvs.get("consumes", [])
        produces = kvs.get("produces", [])

        tail = text[m.end(): m.end()+2000]
        mdecl = METHOD_DECL_RE.search(tail)
        method_name = mdecl.group("mname") if mdecl else None

        http_methods = [http_method] if (http_method and "|" not in http_method) else (
            (http_method.split("|") if http_method else [None])
        )
        base_vals = base_path_vals or [""]

        for b in base_vals:
            for p in paths:
                full_path = normalize_path_join(b, p)
                for hm in http_methods:
                    endpoints.append({
                        "file": java_path.replace("\\", "/"),
                        "class": class_name,
                        "method": method_name,
                        "line": None,
                        "http_method": (hm or "UNKNOWN"),
                        "path": full_path,
                        "consumes": consumes or [],
                        "produces": produces or [],
                        "controller": bool(is_controller),
                        "detected_by": "regex",
                    })
    return endpoints

def scan_project(project_root: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    endpoints_all: List[Dict[str, Any]] = []
    for jp in iter_java_files(project_root):
        txt = safe_read(jp)
        eps = []
        if HAVE_JAVALANG:
            eps = extract_endpoints_ast(jp, txt)
        if not eps:
            eps = extract_endpoints_regex(jp, txt)
        endpoints_all.extend(eps)

    pom = find_pom_xml(project_root)
    deps = parse_pom_dependencies(pom) if pom else []
    return endpoints_all, deps

def main():
    ap = argparse.ArgumentParser(description="Spring/Spring Boot Pre-pass: extract endpoints and deps.")
    ap.add_argument("--project-root", type=str, required=True, help="مسیر ریشه پروژه جاوا")
    ap.add_argument("--out-dir", type=str, default=None, help="مسیر خروجی (پیش‌فرض Desktop/temp)")
    args = ap.parse_args()

    project_root = args.project_root
    out_dir = args.out_dir or get_desktop_temp_dir()
    os.makedirs(out_dir, exist_ok=True)

    print(f"[INFO] شروع اسکن: {project_root}")
    endpoints, deps = scan_project(project_root)

    seen = set()
    uniq_eps = []
    for e in endpoints:
        key = (e["file"], e.get("class"), e.get("method"), e.get("http_method"), e.get("path"))
        if key not in seen:
            seen.add(key)
            uniq_eps.append(e)

    ep_out = os.path.join(out_dir, "spring_endpoints.json")
    deps_out = os.path.join(out_dir, "spring_deps.json")
    write_json(ep_out, uniq_eps)
    write_json(deps_out, deps)

    print(f"[OK] {len(uniq_eps)} endpoint ذخیره شد: {ep_out}")
    print(f"[OK] {len(deps)} dependency استخراج شد: {deps_out}")

if __name__ == "__main__":
    main()
