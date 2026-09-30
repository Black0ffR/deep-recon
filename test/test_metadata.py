#!/usr/bin/env python3
"""Regression test for module 21's Office/PDF metadata extraction.

The original extract_office_metadata() decoded the raw ZIP container as
latin-1 and regexed for <dc:creator>. OOXML (ECMA-376) members are DEFLATE
compressed, so the XML is simply not present in those bytes: for a real
Word/Excel document produced by Office the function returned None and the whole
Office half of the module produced nothing. This test builds genuinely DEFLATEd
docx/xlsx/pptx containers and asserts the metadata is now recovered.
"""
import io
import re
import subprocess
import sys
import zipfile
from pathlib import Path

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "deep_recon.sh")
text = SRC.read_text()

m = re.search(r"<< 'METAEOF'\n(.*?)\nMETAEOF", text, re.S)
if not m:
    print("FAIL: METAEOF payload not found")
    sys.exit(1)
ns: dict = {"__name__": "meta_lib", "doc_urls_file": None,
           "meta_dir": None, "findings": []}
body = m.group(1)
# Keep the helpers, drop the __main__ loop that reads argv and writes files.
body = body.split("all_meta = []")[0]
# Cut everything above the extractors (that block reads sys.argv and checks
# doc_urls_file.exists()), and everything below the second extractor.
start = body.index("MAX_DOC_BYTES")
end   = body.index("all_meta = []") if "all_meta = []" in body else len(body)
import re as _re, struct as _struct, zlib as _zlib, ssl as _ssl
import io as _io, zipfile as _zipfile
import urllib.request as _ur
ns.update(re=_re, struct=_struct, zlib=_zlib, ssl=_ssl, io=_io,
          zipfile=_zipfile, urllib=_ur)
exec(compile(body[start:end], "meta", "exec"), ns)

extract_office = ns["extract_office_metadata"]
extract_pdf = ns["extract_pdf_metadata"]

failures = 0


def check(label, got, exp):
    global failures
    ok = got == exp
    failures += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: got={got!r} exp={exp!r}")


def make_ooxml(name, compression, core_xml):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr(name, core_xml)
    return buf.getvalue()


CORE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:creator>Jordan Rivera</dc:creator>
  <dc:title>Q3 Infrastructure Plan</dc:title>
  <cp:lastModifiedBy>rivera.j</cp:lastModifiedBy>
  <cp:revision>7</cp:revision>
</cp:coreProperties>"""

APP = """<Properties><Application>Microsoft Excel</Application>
<Company>Contoso Ltd</Company></Properties>"""


print("OOXML with DEFLATE (what Word/Excel actually produce)")
deflated = make_ooxml("docProps/core.xml", zipfile.ZIP_DEFLATED, CORE)
check("container really is deflated",
      zipfile.ZipFile(io.BytesIO(deflated)).getinfo("docProps/core.xml").compress_type
      == zipfile.ZIP_DEFLATED, True)
check("raw container hides the XML (the original bug)",
      b"<dc:creator>" in deflated, False)
r = extract_office(deflated, "https://t/x.docx")
check("Author recovered", (r or {}).get("fields", {}).get("Author"), "Jordan Rivera")
check("cp:lastModifiedBy key preserved (report looks for the full key)",
      (r or {}).get("fields", {}).get("cp:lastModifiedBy"), "rivera.j")
check("revision", (r or {}).get("fields", {}).get("cp:revision"), "7")

print("\nOOXML with STORED (the rare case the old code handled)")
stored = make_ooxml("docProps/core.xml", zipfile.ZIP_STORED, CORE)
r = extract_office(stored, "https://t/x.docx")
check("Author recovered", (r or {}).get("fields", {}).get("Author"), "Jordan Rivera")

print("\napp.xml is read too (Application/Company feed the author-leak report)")
both = io.BytesIO()
with zipfile.ZipFile(both, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("docProps/core.xml", CORE)
    z.writestr("docProps/app.xml", APP)
r = extract_office(both.getvalue(), "https://t/x.xlsx")
check("Application", (r or {}).get("fields", {}).get("Application"), "Microsoft Excel")
check("Company", (r or {}).get("fields", {}).get("Company"), "Contoso Ltd")

print("\nNon-OOXML input still returns None (no false positives)")
check("random bytes", extract_office(b"not a zip at all", "x"), None)
check("OLE2 magic", extract_office(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "x"), None)

print("\nPDF: uncompressed Info dictionary")
pdf = (b"%PDF-1.4\n1 0 obj\n<< /Author (Alice Example) /Producer (Skia/PDF m118) "
       b"/CreationDate (D:20240101000000Z) >>\nendobj\ntrailer\n%%EOF\n")
r = extract_pdf(pdf, "https://t/x.pdf")
check("Author", (r or {}).get("fields", {}).get("Author"), "Alice Example")
check("Producer", (r or {}).get("fields", {}).get("Producer"), "Skia/PDF m118")

print("\nPDF: Info dictionary inside a Flate object stream (PDF 1.5+)")
import zlib
inner = b"<< /Author (Bob Compressed) /Producer (Acme PDF 9.9) >>"
comp = zlib.compress(inner)
pdf2 = (b"%PDF-1.7\n1 0 obj\n<< /Length " + str(len(comp)).encode() +
        b" /Filter /FlateDecode >>\nstream\n" + comp + b"\nendstream\ntrailer\n%%EOF\n")
r = extract_pdf(pdf2, "https://t/x.pdf")
check("Author from compressed stream", (r or {}).get("fields", {}).get("Author"),
      "Bob Compressed")

print("\nDownload is bounded")
check("MAX_DOC_BYTES defined", ns["MAX_DOC_BYTES"] <= 16 << 20, True)

print(f"\n{'ALL CHECKS PASSED' if not failures else f'{failures} CHECK(S) FAILED'}")
sys.exit(1 if failures else 0)
