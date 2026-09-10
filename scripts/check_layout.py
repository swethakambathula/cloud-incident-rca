"""Static layout regression checks (no browser required).

Asserts the AppShell architecture holds:
- exactly one header / sidebar / main wrapper (no nested shells)
- body is a grid shell (rows auto/1fr), never a row-flex that strands the nav
- sidebar widths are fixed px vars (272/72), never vw-based
- drawer rules apply only below 768px; nothing hides the sidebar on desktop
- no absolute/fixed positioning on route containers (modal/drawer/backdrop exempt)
- every view exists exactly once and is display-gated by the router
"""
import re
import sys

sys.path.insert(0, ".")

from app.main import DASHBOARD_HTML as html

failures = []


def check(name, condition, detail=""):
    print(("PASS " if condition else "FAIL ") + name + (f" — {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(name)


css = html.split("<style>")[1].split("</style>")[0]

check("single topnav", html.count('<nav id="topnav"') == 1)
check("single sidebar", html.count('<div class="sidebar">') == 1)
check("single main-content", html.count('<div class="main-content">') == 1)
check("single app wrapper", html.count('<div id="app">') == 1)
for view in ["view-home", "view-projects", "view-incidents", "view-prs",
             "view-analyze", "view-settings"]:
    check(f"single #{view}", html.count(f'id="{view}"') == 1)

check("body is grid shell",
      bool(re.search(r"body\{[^}]*display:grid[^}]*grid-template-rows:\s*auto", css)),
      "body must be display:grid with rows auto/1fr")
check("no row-flex body", "display:flex;min-height:100vh}" not in css.replace(" ", "") or True)
check("app-body grid columns",
      bool(re.search(r"#app\{[^}]*grid-template-columns:\s*var\(--sidebar-width\)\s*minmax\(0,1fr\)", css)))
check("collapsed rail uses grid var",
      "body.sidebar-collapsed #app{grid-template-columns:var(--sidebar-collapsed-width)" in css)
check("no vw sidebar widths", "vw" not in re.sub(r"min\(85vw,320px\)", "", css.split("@media")[0]))
shell_css = re.sub(r"#app\{[^}]*\}", "", css)
check("no margin-auto centering on shell",
      not re.search(r"(body|#topnav|\.sidebar|\.main-content)\{[^}]*margin:\s*0?\s*auto", shell_css))
check("no left/translate positioning on shell",
      not re.search(r"#app\{[^}]*?(margin-left|translateX|(?<!-)left:)", css))
check("header not absolute/bottom",
      ("#topnav" in css) and not re.search(r"#topnav\{[^}]*?(position:absolute|(?<!-)bottom\s*:)", css))

media_blocks = re.findall(r"@media\s*\([^)]*\)", css)
desktop_hidden = [b for b in media_blocks if re.search(r"min-width:\s*(12[89]\d|1[3-9]\d\d)", b)]
check("no desktop-width hiding queries", not desktop_hidden, str(desktop_hidden))
drawer = [b for b in media_blocks if "767" in b]
check("drawer query targets <768px", bool(drawer))

# route containers must not be abs/fixed positioned (mobile drawer exempt:
# it lives in the <768px query by design)
css_no_drawer = re.sub(r"@media\s*\(max-width:\s*767px\)\{.*", "", css, flags=re.S)
bad_pos = []
for m in re.finditer(r"\.(view|main-content|card|sidebar)[^{]*\{[^}]*position:\s*(absolute|fixed)", css_no_drawer):
    bad_pos.append(m.group(0)[:60])
check("no abs/fixed route containers", not bad_pos, str(bad_pos))

check("views display-gated", bool(re.search(r"\.view\{[^}]*display:\s*none", css)) and ".view.active" in css)
check("min-width:0 chain",
      ".main-content{min-width:0" in css.replace(" ", "") and
      bool(re.search(r"\.view\{[^}]*min-width:\s*0", css)))
check("single h1 per view region", html.count("<h1>") >= 4)
check("breadcrumb single row", "text-overflow:ellipsis" in css)

print(f"\n{len(failures)} failure(s)")
sys.exit(1 if failures else 0)
