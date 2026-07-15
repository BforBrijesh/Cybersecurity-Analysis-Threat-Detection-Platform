import sys, sqlite3, ast, pathlib
sys.path.insert(0, '.')

# Syntax check
fail = []
for d in ['.', 'pages', 'database', 'utils', 'engine']:
    for f in pathlib.Path(d).glob('*.py'):
        try:
            ast.parse(f.read_text(encoding='utf-8'))
        except SyntaxError as e:
            fail.append(str(f) + ': ' + str(e))
print("Syntax:", "All OK" if not fail else str(fail))

# DB check
from database.db import init_db, seed_accounts, verify_user
init_db()
seed_accounts()

conn = sqlite3.connect('database/cybershield.db')
rows = conn.execute("SELECT id, username, email, full_name, role, status FROM users ORDER BY id").fetchall()
conn.close()

print("\nDatabase users (only admin should exist):")
for r in rows:
    print("  ID:{} | {} | {} | {} | {} | {}".format(*r))

print("\nLogin test:")
ok, data = verify_user('brijesh_parmar', 'Admin@2026')
print("  brijesh_parmar / Admin@2026 -> OK={} role={}".format(ok, data.get('role','?')))
