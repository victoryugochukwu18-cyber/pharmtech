"""Pure helpers for the audit trail: change detection and a tamper-evident hash chain."""
import hashlib
import json

IGNORE = {"audit", "log", "ts", "seq", "rlog", "users"}
COLL = {
    "stock": [("items", "Drug"), ("batches", "Batch")],
    "qms": [("recs", "Record")],
    "lab": [("samples", "Sample")],
    "phyto": [("plants", "Plant"), ("cmps", "Compound")],
}
ITEM_FIELDS = ["name", "unit", "storage", "reorder level"]
MAX_ENTRIES = 60


def short(v, n=70):
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    return s if len(s) <= n else s[: n - 1] + "..."


def desc(old, new, path=""):
    out = []
    if isinstance(old, dict) and isinstance(new, dict):
        for k in sorted(set(old) | set(new)):
            if k in IGNORE:
                continue
            p = f"{path}.{k}" if path else k
            if k not in old:
                out.append(f"{p} added: {short(new[k])}")
            elif k not in new:
                out.append(f"{p} removed")
            else:
                out += desc(old[k], new[k], p)
    elif isinstance(old, list) and isinstance(new, list):
        if len(old) != len(new):
            out.append(f"{path or 'list'}: {len(old)} -> {len(new)} items")
        elif old != new:
            out.append(f"{path or 'list'} edited")
    elif old != new:
        out.append(f"{path or 'value'}: {short(old)} -> {short(new)}")
    return out


def rid(coll, rec, idx):
    if isinstance(rec, dict):
        if coll == "batches":
            return f"{rec.get('code', '?')}/{rec.get('batch', '?')}"
        return str(rec.get("id", idx))
    return str(idx)


def label(section, coll, rec, state):
    if not isinstance(rec, dict):
        return ""
    if section == "stock" and coll == "batches":
        items = state.get("items") or {}
        name = (items.get(rec.get("code")) or [rec.get("code")])[0]
        return f"{name} batch {rec.get('batch')}"
    if section == "qms":
        return f"{rec.get('id', '')} {(rec.get('f') or {}).get('title', '')}".strip()
    if section == "lab":
        return f"{rec.get('id', '')} {rec.get('name', '')}".strip()
    if section == "phyto":
        return rec.get("sci") or rec.get("name") or str(rec.get("id", ""))
    return ""


def log_line(x):
    t = x.get("type")
    base = f"{x.get('name', '')} batch {x.get('batch', '')} qty {x.get('q', '')}"
    if t == "receive":
        return ("Stock received", base)
    if t == "writeoff":
        return ("Stock written off", base)
    if t == "status":
        return ("Batch status changed", f"{base}: {x.get('note', '')}")
    return ("Stock issued", base + (" (FEFO)" if x.get("fefo") else " (not FEFO)"))


def diff_section(section, old, new):
    """Return a list of (record, action, detail) describing what changed."""
    out = []
    old, new = old or {}, new or {}
    used = set()
    for coll, noun in COLL.get(section, []):
        used.add(coll)
        o, n = old.get(coll), new.get(coll)
        if section == "stock" and coll == "items":
            o, n = o or {}, n or {}
            for code in sorted(set(o) | set(n)):
                nm = ((n.get(code) or o.get(code) or [code]) or [code])[0]
                if code not in o:
                    out.append((nm, "Created", "Drug added"))
                elif code not in n:
                    out.append((nm, "Removed", ""))
                elif o[code] != n[code]:
                    ch = [f"{ITEM_FIELDS[i] if i < len(ITEM_FIELDS) else i}: {short(o[code][i] if i < len(o[code]) else '')} -> {short(n[code][i] if i < len(n[code]) else '')}"
                          for i in range(max(len(o[code]), len(n[code])))
                          if (o[code][i] if i < len(o[code]) else None) != (n[code][i] if i < len(n[code]) else None)]
                    out.append((nm, "Changed", "; ".join(ch)[:900]))
            continue
        om = {rid(coll, r, i): r for i, r in enumerate(o or [])}
        nm_ = {rid(coll, r, i): r for i, r in enumerate(n or [])}
        for k in nm_:
            if k not in om:
                out.append((label(section, coll, nm_[k], new) or k, "Created", noun + " added"))
        for k in om:
            if k not in nm_:
                out.append((label(section, coll, om[k], old) or k, "Removed", noun + " removed"))
        for k in nm_:
            if k in om and om[k] != nm_[k]:
                d = desc(om[k], nm_[k])
                if d:
                    out.append((label(section, coll, nm_[k], new) or k, "Changed", "; ".join(d)[:900]))
    if section == "stock":
        seen = {(x.get("ts"), x.get("batch"), x.get("q")) for x in (old.get("log") or [])}
        for x in reversed([x for x in (new.get("log") or []) if (x.get("ts"), x.get("batch"), x.get("q")) not in seen]):
            action, detail = log_line(x)
            out.append((x.get("name", ""), action, detail))
    rest_old = {k: v for k, v in old.items() if k not in used}
    rest_new = {k: v for k, v in new.items() if k not in used}
    d = desc(rest_old, rest_new)
    if d:
        out.append(("(settings)", "Changed", "; ".join(d)[:900]))
    if len(out) > MAX_ENTRIES:
        extra = len(out) - MAX_ENTRIES
        out = out[:MAX_ENTRIES] + [("(many)", "Changed", f"{extra} further changes in this save")]
    return out


def chain_hash(prev, at_iso, who, who_id, section, record, action, detail):
    body = json.dumps([at_iso, who, who_id, section, record, action, detail], ensure_ascii=False, sort_keys=True)
    return hashlib.sha256((prev + "|" + body).encode()).hexdigest()
