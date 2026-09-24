"""Extract an XML schema printed in a 3GPP specification (.docx) to a file.

    python3 tools/spec/extract_xsd.py SPEC.docx TARGET_NAMESPACE OUT.xsd

The schemas in TS 24.379 and TS 24.481 are printed as text in an annex and are
not shipped as files. This takes the paragraph text of the .docx -- never a PDF,
whose table and layout extraction invents structure -- finds the <xs:schema>
element declaring TARGET_NAMESPACE, and writes it verbatim from its XML
declaration to </xs:schema>, prefixed by a provenance comment. It refuses to
write anything that does not parse as XML.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

from docx import Document


def paragraphs(path: Path):
    for p in Document(str(path)).element.body.iter():
        if p.tag.endswith("}p"):
            yield "".join(t.text or "" for t in p.iter() if t.tag.endswith("}t"))


def extract(docx: Path, namespace: str) -> str:
    lines = list(paragraphs(docx))
    hit = next((i for i, l in enumerate(lines)
                if f'targetNamespace="{namespace}"' in l), None)
    if hit is None:
        raise SystemExit(f"no schema with targetNamespace {namespace!r} in {docx.name}")
    start = next(i for i in range(hit, -1, -1)
                 if lines[i].lstrip().startswith(("<?xml", "<xs:schema")))
    if start > 0 and lines[start - 1].lstrip().startswith("<?xml"):
        start -= 1
    end = next(i for i in range(hit, len(lines)) if "</xs:schema>" in lines[i])
    text = "\n".join(l.replace(" ", " ") for l in lines[start:end + 1]) + "\n"
    ET.fromstring(text.split("?>", 1)[1] if text.lstrip().startswith("<?xml") else text)
    return text


def main() -> int:
    docx, namespace, out = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    body = extract(docx, namespace)
    digest = hashlib.sha256(docx.read_bytes()).hexdigest()[:16]
    head, sep, rest = body.partition("?>")
    prov = (f"<!-- Extracted verbatim by tools/spec/extract_xsd.py from {docx.name}\n"
            f"     (sha256 {digest}...), targetNamespace {namespace}. Do not edit:\n"
            f"     re-extract. -->\n")
    out.write_text(head + sep + "\n" + prov + rest.lstrip("\n") if sep else prov + body)
    print(f"{out}: {len(body.splitlines())} lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
