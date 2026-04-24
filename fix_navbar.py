import re

path = "templates/home.html"

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Replace the entire navbar block with one that has the buttons
old = re.search(r'<nav class="navbar">.*?</nav>', content, re.DOTALL)
if old:
    print("Found navbar at:", old.start(), "-", old.end())
    print("Current navbar content:")
    print(old.group())
else:
    print("ERROR: Could not find navbar!")

new_nav = '''<nav class="navbar">
    <a href="/" class="brand"><i class="fas fa-shield-alt"></i> VeriScope AI</a>
    <div style="display:flex; gap:12px; align-items:center; flex-shrink:0;">
        <a href="/login" style="display:inline-block; text-decoration:none; color:#ffffff; font-weight:600; padding:9px 22px; border:1.5px solid #94a3b8; border-radius:999px; font-size:14px; background:transparent;">Log in</a>
        <a href="/register" style="display:inline-block; text-decoration:none; background:#ffffff; color:#000000; font-weight:700; padding:9px 22px; border-radius:999px; font-size:14px;">Sign up for free</a>
    </div>
</nav>'''

new_content = re.sub(r'<nav class="navbar">.*?</nav>', new_nav, content, flags=re.DOTALL)

with open(path, "w", encoding="utf-8") as f:
    f.write(new_content)

print("\nDONE! Verifying...")
with open(path, "r", encoding="utf-8") as f:
    result = f.read()
    if "Log in" in result:
        print("SUCCESS: Buttons are now in home.html!")
    else:
        print("FAILED: Buttons not found!")
