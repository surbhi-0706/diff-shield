import sys
from pathlib import Path

import block_parser

diff_java_multiline = '''--- a/Exec.java
+++ b/Exec.java
@@ -10,4 +10,2 @@
-    if (!isValid(cmd)) {
-        return null;
-    }
     Runtime.getRuntime().exec(cmd);'''

diff_py_multiline = '''--- a/runner.py
+++ b/runner.py
@@ -10,3 +10,2 @@
-    if not is_safe(cmd):
-        raise ValueError()
     os.system(cmd)'''

diff_c_multiline = '''--- a/str.c
+++ b/str.c
@@ -10,3 +10,2 @@
-    if (strlen(src) >= sizeof(dest)) return;
     strcpy(dest, src);'''

diff_html_multiline = '''--- a/index.html
+++ b/index.html
@@ -5,2 +5,1 @@
-    <!-- if safe --> <button onclick="run()"></button>
     <button onclick="run()"></button>'''

for name, diff in [("Java", diff_java_multiline), ("Python", diff_py_multiline), ("C/C++", diff_c_multiline), ("HTML", diff_html_multiline)]:
    parsed = block_parser.parse_diff_blocks(diff)
    print(f"=== {name} ===")
    for f in parsed["files"]:
        print(f"File: {f['file_path']} | Lang: {f['language']}")
        for h in f["hunks"]:
            print(f"  Removed blocks: {len(h['removed_blocks'])}")
            print(f"  Hunk sinks: {h['hunk_sinks']}")
