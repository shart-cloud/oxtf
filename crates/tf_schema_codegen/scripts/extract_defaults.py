#!/usr/bin/env python3
"""Q5 experiment: how much of the defaults overlay can be derived automatically?

Extracts (resource, attribute path) -> default value pairs two ways:

  docs:   "Defaults to `x`" / "Default is `x`" / "(Optional, Default: x)" /
          "Default value is `X`" phrases in website/docs/r/*.html.markdown
  source: `Default: <literal>` (SDKv2) and `Default: booldefault.StaticBool(x)`
          etc. (plugin framework) in the provider's Go schema definitions

and validates every candidate against the committed schema JSON (the path
must exist and the literal must fit the attribute's type).

Usage:
  extract_defaults.py aws    /path/to/terraform-provider-aws    schemas/providers/aws.json    OUT.jsonl
  extract_defaults.py google /path/to/terraform-provider-google schemas/providers/google.json OUT.jsonl

Prints summary counts; writes one JSON object per extraction to OUT.jsonl.
Stdlib only.
"""

import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# schema helpers
# ---------------------------------------------------------------------------


def load_schema(path):
    d = json.load(open(path))
    (ps,) = d["provider_schemas"].values()
    return ps["resource_schemas"]


def resolve(block, path):
    """Return the cty type (or 'block') at `path` inside a schema block, or None."""
    cur = ("block", block)
    for i, seg in enumerate(path):
        last = i == len(path) - 1
        kind, node = cur
        if kind == "block":
            if seg in node.get("attributes", {}):
                t = node["attributes"][seg].get("type")
                if last:
                    return t
                # attributes-as-blocks: descend through list/set of object
                while isinstance(t, list) and t[0] in ("list", "set", "map"):
                    t = t[1]
                if isinstance(t, list) and t[0] == "object":
                    cur = ("object", t[1])
                    continue
                return None
            if seg in node.get("block_types", {}):
                if last:
                    return "block"
                cur = ("block", node["block_types"][seg]["block"])
                continue
            return None
        else:  # object
            if seg not in node:
                return None
            t = node[seg]
            if last:
                return t
            while isinstance(t, list) and t[0] in ("list", "set", "map"):
                t = t[1]
            if isinstance(t, list) and t[0] == "object":
                cur = ("object", t[1])
                continue
            return None
    return None


def all_paths(block, prefix=()):
    for a in block.get("attributes", {}):
        yield prefix + (a,)
    for b, bt in block.get("block_types", {}).items():
        yield prefix + (b,)
        yield from all_paths(bt["block"], prefix + (b,))


NUM = re.compile(r"^-?\d+(\.\d+)?$")


def typed_value(raw, ty):
    """Coerce a raw literal to the attribute type; None if it does not fit."""
    if raw is None:
        return None
    raw = raw.strip()
    if ty == "bool":
        if raw in ("true", "false"):
            return raw == "true"
        return None
    if ty == "number":
        if NUM.match(raw):
            return float(raw)
        return None
    if ty == "string":
        while len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'`":
            raw = raw[1:-1]
        return raw
    return None


# ---------------------------------------------------------------------------
# docs
# ---------------------------------------------------------------------------

DOC_ARG = re.compile(r"^\s*[*-]\s+`([a-z0-9_]+)`\s*-?\s*(.*)$")
DOC_DEFAULT = re.compile(
    r"(?:\bdefaults? to|\bdefault is|\bdefault value is|\bdefault:|\bdefault\b)\s*"
    r"(`[^`]*`|\"[^\"]*\"|true\b|false\b|-?\d+(?:\.\d+)?\b)",
    re.I,
)
HEADING = re.compile(r"^#+\s+(.*)$")


def docs_extract(provider, repo, schemas):
    out = []
    ddir = os.path.join(repo, "website/docs/r")
    for fn in sorted(os.listdir(ddir)):
        if not fn.endswith(".html.markdown"):
            continue
        res = f"{provider}_{fn[: -len('.html.markdown')]}"
        if res not in schemas:
            continue
        block = schemas[res]["block"]
        section = None
        in_args = False
        raw_lines = open(os.path.join(ddir, fn), encoding="utf-8").read().split("\n")
        lines = []  # (lineno, logical line): argument entries joined with their continuation lines
        for ln, line in enumerate(raw_lines, 1):
            if lines and DOC_ARG.match(lines[-1][1]) and line.startswith("  ") and line.strip() and not DOC_ARG.match(line):
                lines[-1] = (lines[-1][0], lines[-1][1] + " " + line.strip())
            else:
                lines.append((ln, line))
        for ln, line in lines:
            h = HEADING.match(line)
            if h:
                title = h.group(1).strip()
                low = title.lower()
                if "argument" in low and "reference" in low:
                    in_args, section = True, None
                elif ("attribute" in low and "reference" in low) or low.startswith("import"):
                    in_args, section = False, None
                elif low.startswith("timeouts"):
                    in_args, section = False, "timeouts"
                else:
                    m = re.search(r"`([a-z0-9_]+)`", title)
                    if m:
                        section = m.group(1)
                    else:
                        words = re.sub(r"\b(configuration )?(block|blocks|arguments?)\b", "", low).strip()
                        section = re.sub(r"[^a-z0-9]+", "_", words).strip("_") or None
                continue
            m = DOC_ARG.match(line)
            if not m:
                continue
            name, text = m.group(1), m.group(2)
            d = DOC_DEFAULT.search(text)
            if not d:
                continue
            raw = d.group(1)
            # candidate paths: top level (argument section) or nested under the heading's block
            cands = []
            if in_args and section is None:
                cands.append((name,))
            if section:
                cands += [p for p in all_paths(block) if len(p) >= 2 and p[-1] == name and p[-2] == section]
            if not cands:
                # fall back to a unique nested path ending in `name`
                anywhere = [p for p in all_paths(block) if p[-1] == name]
                if len(anywhere) == 1:
                    cands.append(anywhere[0])
            path, ty = None, None
            for c in cands:
                t = resolve(block, list(c))
                if t is not None and t != "block":
                    path, ty = c, t
                    break
            rec = dict(method="docs", resource=res, raw=raw, name=name, loc=f"{fn}:{ln}")
            if path is None:
                rec["status"] = "unresolved_path"
            else:
                v = typed_value(raw.strip("`\"") if ty != "string" else raw, ty)
                if v is not None and ty == "number" and re.match(r"\s*(seconds?|minutes?|hours?|days?|mib|mb|kb|kib|gb|gib)\b", text[d.end():], re.I):
                    rec["unit_suffix"] = text[d.end():].split()[0]
                rec["path"] = ".".join(path)
                if v is None:
                    rec["status"] = "type_mismatch"
                    rec["type"] = json.dumps(ty)
                else:
                    rec["status"] = "ok"
                    rec["value"] = v
            out.append(rec)
    return out


# ---------------------------------------------------------------------------
# Go source
# ---------------------------------------------------------------------------


def mask_strings(src):
    """Blank out string/comment contents (same length) so brace matching is safe."""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"' and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = " "
            i = j + 1
        elif c == "`":
            j = src.find("`", i + 1)
            j = n if j < 0 else j
            for k in range(i + 1, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


KEY_BEFORE_BRACE = re.compile(
    r'(?:"([a-zA-Z0-9_]+)"|names\.(Attr\w+))\s*:\s*(?:&?schema\.\w+|\w+\.\w+Attribute|\w+\.\w+Block)?\s*$'
)
DEFAULT_RE = re.compile(r"\bDefault:\s*([^\n]+?),?\s*(?://.*)?\n")
FW_DEFAULT = re.compile(r"^\w+default\.Static(?:Bool|String|Int64|Int32|Float64|Number)\((.*)\)$")


def resolve_names_consts(repo):
    consts = {}
    p = os.path.join(repo, "names/attr_consts_gen.go")
    if os.path.exists(p):
        for m in re.finditer(r'(Attr\w+)\s*=\s*"([^"]+)"', open(p).read()):
            consts[m.group(1)] = m.group(2)
    return consts


def enclosing_chain(src, masked, pos, consts):
    """Names of keyed `{` scopes enclosing pos, innermost first, plus enclosing func name."""
    chain = []
    depth = 0
    i = pos
    func = None
    while i > 0:
        i -= 1
        c = masked[i]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth > 0:
                depth -= 1
                continue
            before = src[max(0, i - 200) : i]
            m = KEY_BEFORE_BRACE.search(before)
            if m:
                name = m.group(1) or consts.get(m.group(2), None)
                chain.append(name or f"?{m.group(2)}")
            ls = src.rfind("\n", 0, i) + 1
            fm = re.match(r"func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(", src[ls:i])
            if fm:
                func = fm.group(1)
                break
    return chain, func


def parse_go_default(expr, consts):
    expr = expr.strip().rstrip(",")
    m = FW_DEFAULT.match(expr)
    if m:
        expr = m.group(1).strip()
    if expr in ("true", "false") or NUM.match(expr):
        return expr, True
    if re.match(r'^"[^"]*"$', expr):
        return expr, True
    if expr.startswith("names.Attr") and expr[6:] in consts:
        return '"' + consts[expr[6:]] + '"', True
    return expr, False


def go_files(root):
    for d, _, fs in os.walk(root):
        for f in fs:
            if f.endswith(".go") and not f.endswith("_test.go"):
                yield os.path.join(d, f)


def source_extract(provider, repo, schemas):
    consts = resolve_names_consts(repo)
    out = []
    if provider == "aws":
        root = os.path.join(repo, "internal/service")
        func_to_res = {}
    else:
        root = os.path.join(repo, "google/services")
        func_to_res = {}
        # google 8.x: each resource registers itself in an init() with
        # registry.Schema{Name: "google_x", Type: registry.SchemaTypeResource, Schema: ResourceX()}
        reg = re.compile(
            r'registry\.Schema\{[^}]*?Name:\s*"(google_[a-z0-9_]+)"[^}]*?Type:\s*registry\.SchemaTypeResource[^}]*?Schema:\s*(?:\w+\.)?(\w+)\(\)'
        )
        for pf in go_files(root):
            text = open(pf, encoding="utf-8").read()
            if "SchemaTypeResource" in text:
                for m in reg.finditer(text):
                    func_to_res.setdefault(m.group(2), m.group(1))
    ann_re = re.compile(r'@(?:SDK|Framework)Resource\("([a-z0-9_]+)"')
    for path in go_files(root):
        src = open(path, encoding="utf-8").read()
        if "Default" not in src:
            continue
        masked = mask_strings(src)
        anns = [(m.start(), m.group(1)) for m in ann_re.finditer(src)]
        res_funcs = {}
        for m in re.finditer(r"\nfunc\s+(\w+)\(\)\s*\*schema\.Resource\s*\{", src):
            if m.group(1) in func_to_res:
                res_funcs[m.group(1)] = func_to_res[m.group(1)]
        for m in DEFAULT_RE.finditer(masked):
            # read expression from original text
            line_end = src.find("\n", m.start())
            expr = src[m.start() + len("Default:") : line_end].split("//")[0].strip().rstrip(",").strip()
            chain, func = enclosing_chain(src, masked, m.start(), consts)
            # resource attribution
            res = None
            if provider == "aws":
                if len(anns) == 1:
                    res = anns[0][1]
                elif anns:
                    prev = [a for a in anns if a[0] < m.start()]
                    res = (prev[-1] if prev else anns[0])[1]
            else:
                if func in res_funcs:
                    res = res_funcs[func]
                elif len(res_funcs) == 1:
                    res = next(iter(res_funcs.values()))
            loc = f"{os.path.relpath(path, repo)}:{src.count(chr(10), 0, m.start()) + 1}"
            rec = dict(method="source", resource=res, raw=expr, chain=list(reversed(chain)), loc=loc)
            if res is None or res not in schemas:
                rec["status"] = "no_resource"
                out.append(rec)
                continue
            if not chain or any(c is None or c.startswith("?") for c in chain):
                rec["status"] = "no_key"
                out.append(rec)
                continue
            block = schemas[res]["block"]
            p = list(reversed(chain))
            ty = resolve(block, p)
            if ty is None or ty == "block":
                # schema defined in a helper func: try suffixes that resolve uniquely
                cands = [q for q in all_paths(block) if q[-len(p):] == tuple(p)]
                if len(cands) == 1:
                    p = list(cands[0])
                    ty = resolve(block, p)
                    rec["suffix_match"] = True
            if ty is None or ty == "block":
                rec["status"] = "unresolved_path"
                out.append(rec)
                continue
            raw, literal = parse_go_default(expr, consts)
            rec["path"] = ".".join(p)
            if not literal:
                rec["status"] = "non_literal"
                out.append(rec)
                continue
            v = typed_value(raw, ty)
            if v is None:
                rec["status"] = "type_mismatch"
                rec["type"] = json.dumps(ty)
            else:
                rec["status"] = "ok"
                rec["value"] = v
            out.append(rec)
    return out


# ---------------------------------------------------------------------------


def main():
    provider, repo, schema_path, out_path = sys.argv[1:5]
    schemas = load_schema(schema_path)
    docs = docs_extract(provider, repo, schemas)
    src = source_extract(provider, repo, schemas)
    with open(out_path, "w") as f:
        for r in docs + src:
            f.write(json.dumps(r) + "\n")

    def summary(recs, name):
        st = {}
        for r in recs:
            st[r["status"]] = st.get(r["status"], 0) + 1
        ok = {(r["resource"], r["path"]): r["value"] for r in recs if r["status"] == "ok"}
        res = {k[0] for k in ok}
        top = sum(1 for k in ok if "." not in k[1])
        print(f"{name}: candidates={len(recs)} by status={dict(sorted(st.items()))}")
        print(f"{name}: distinct validated (resource, path) defaults={len(ok)} (top-level {top}, nested {len(ok) - top}) across {len(res)} resources")
        nt = {k: v for k, v in ok.items() if not k[1].startswith("timeouts.")}
        nb = sum(1 for v in nt.values() if isinstance(v, bool))
        print(f"{name}: excluding timeouts.*: {len(nt)} defaults across {len({k[0] for k in nt})} resources; bool-valued {nb}")
        return nt

    d = summary(docs, "docs")
    s = summary(src, "source")
    both = set(d) & set(s)
    agree = sum(1 for k in both if d[k] == s[k])
    print(f"overlap: {len(both)} pairs in both; agree={agree} disagree={len(both) - agree}")
    print(f"docs only: {len(set(d) - set(s))}  source only: {len(set(s) - set(d))}  union: {len(set(d) | set(s))}")
    for k in sorted(both):
        if d[k] != s[k]:
            print(f"  DISAGREE {k[0]}.{k[1]}: docs={d[k]!r} source={s[k]!r}")
    print(f"resources in schema: {len(schemas)}  (overlap/union figures exclude timeouts.*)")


if __name__ == "__main__":
    main()
