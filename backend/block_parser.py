import re
from typing import Dict, List, Any

SECURITY_TARGETS = {
    "PROTOTYPE_POLLUTION": [r"__proto__", r"constructor", r"prototype"],
    "CODE_INJECTION": [r"\beval\(", r"\bFunction\(", r"setTimeout\(", r"exec\("],
    "DOM_XSS": [r"innerHTML", r"outerHTML", r"document\.write"],
    "SQL_INJECTION": [r"SELECT\b", r"INSERT\b", r"UPDATE\b", r"DELETE\b", r"WHERE\b"]
}

def normalize_line(line: str) -> str:
    cleaned = line.strip()
    cleaned = cleaned.replace("'", '"').replace("`", '"')
    cleaned = cleaned.replace("===", "==")
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned

def classify_block(line: str) -> Dict[str, Any]:
    norm = normalize_line(line)
    
    # 1. Loop / Iterator Entry Block
    if re.search(r"^\b(for|while|do)\b|\.forEach\(|\.map\(", norm):
        return {"type": "LOOP_ENTRY", "raw": line, "normalized": norm, "protects": None}
        
    # 2. Guard / Sanitizer Condition Block
    if re.search(r"^\bif\b|\bcontinue\b|\breturn\b|\bbreak\b", norm):
        protects_category = None
        for category, patterns in SECURITY_TARGETS.items():
            if any(re.search(p, norm, re.IGNORECASE) for p in patterns):
                protects_category = category
                break
        return {"type": "GUARD_CONDITION", "raw": line, "normalized": norm, "protects": protects_category}
        
    # 3. Execution / Sink Block
    if re.search(r"\[.+\]\s*=|\.set\(|\.assign\(", norm):
        return {"type": "MUTATION_SINK", "raw": line, "normalized": norm, "protects": None}

    # 4. General Statement
    return {"type": "STATEMENT", "raw": line, "normalized": norm, "protects": None}

def parse_diff_blocks(raw_diff: str) -> Dict[str, List[Dict[str, Any]]]:
    removed_blocks = []
    added_blocks = []
    for line in raw_diff.splitlines():
        if line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
            continue
        if line.startswith("-"):
            actual_code = line[1:].strip()
            if actual_code:
                removed_blocks.append(classify_block(actual_code))
        elif line.startswith("+"):
            actual_code = line[1:].strip()
            if actual_code:
                added_blocks.append(classify_block(actual_code))
    return {"removed_blocks": removed_blocks, "added_blocks": added_blocks}