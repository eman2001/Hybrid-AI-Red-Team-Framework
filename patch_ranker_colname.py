path = "engine/modules/exploiter/exploit_ranker.py"
with open(path, encoding="utf-8") as f:
    content = f.read()

with open(path + ".bak2", "w", encoding="utf-8") as f:
    f.write(content)
print("Backup saved: exploit_ranker.py.bak2")

old = '''X = pd.DataFrame([[cvss, etype, port]], columns=["cvss_score", "exploit_type", "port"])'''
new = '''X = pd.DataFrame([[cvss, etype, port]], columns=["cvss_score", "exploit_type_enc", "port"])'''

if old not in content:
    print("ERROR: expected line not found -- manual edit needed.")
else:
    content = content.replace(old, new, 1)
    print("OK: column name fixed to match training (exploit_type_enc)")

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
