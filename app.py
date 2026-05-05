from flask import Flask, request, render_template, redirect, url_for, session, g
import sqlite3
import os
import hashlib

app = Flask(__name__)
app.secret_key = 'vuln_machine_secret'

DATABASE = 'vulnerable.db'

# ─────────────────────────────────────────────
# DB helpers
# ─────────────────────────────────────────────

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

# ─────────────────────────────────────────────
# HOME
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

# ═══════════════════════════════════════════════════════════════
# CHALLENGE 1 – Login Bypass
#   FLAG_1A (Nivel 1 – sin filtro)
#   FLAG_1B (Nivel 2 – WAF básico bypasseable)
# ═══════════════════════════════════════════════════════════════

@app.route('/challenge/1')
def challenge1():
    return render_template('challenge1.html')

@app.route('/challenge/1/level1', methods=['GET', 'POST'])
def c1_level1():
    result = error = flag = None
    if request.method == 'POST':
        user = request.form.get('username', '')
        pwd  = request.form.get('password', '')
        try:
            db = sqlite3.connect(DATABASE)
            cur = db.cursor()
            # Completamente vulnerable
            query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"
            cur.execute(query)
            row = cur.fetchone()
            db.close()
            if row:
                flag = "FLAG{1A_4dm1n_bypass_sqli_b4sic}"
                result = dict(zip([d[0] for d in cur.description] if cur.description else [], row)) if row else None
            else:
                error = "Credenciales incorrectas."
        except Exception as e:
            error = str(e)
    return render_template('c1_level1.html', result=result, error=error, flag=flag)

@app.route('/challenge/1/level2', methods=['GET', 'POST'])
def c1_level2():
    result = error = flag = None
    if request.method == 'POST':
        user = request.form.get('username', '')
        pwd  = request.form.get('password', '')
        # WAF básico que bloquea solo la palabra "or" en minúsculas
        blocked = ["or", "union", "select", "drop"]
        user_lower = user.lower()
        if any(b in user_lower for b in blocked):
            error = "⚠️ WAF: Entrada bloqueada por política de seguridad."
        else:
            try:
                db = sqlite3.connect(DATABASE)
                cur = db.cursor()
                query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"
                cur.execute(query)
                row = cur.fetchone()
                db.close()
                if row:
                    flag = "FLAG{1B_w4f_bypass_case_OR_1=1}"
                    result = "Acceso concedido como administrador"
                else:
                    error = "Credenciales incorrectas."
            except Exception as e:
                error = str(e)
    return render_template('c1_level2.html', result=result, error=error, flag=flag)

# ═══════════════════════════════════════════════════════════════
# CHALLENGE 2 – Error-Based SQLi (extracción de datos)
#   FLAG_2A (Nivel 1 – mensajes de error expuestos)
#   FLAG_2B (Nivel 2 – con validación de tipo numérico, bypasseable)
# ═══════════════════════════════════════════════════════════════

@app.route('/challenge/2')
def challenge2():
    return render_template('challenge2.html')

@app.route('/challenge/2/level1')
def c2_level1():
    product_id = request.args.get('id', '1')
    result = error = flag = None
    try:
        db = sqlite3.connect(DATABASE)
        cur = db.cursor()
        query = f"SELECT * FROM products WHERE id={product_id}"
        cur.execute(query)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        db.close()
        result = [dict(zip(cols, r)) for r in rows]
        # Si extrae secretos, otorgar bandera
        if any('FLAG' in str(r) for r in rows):
            flag = "FLAG{2A_err0r_based_data_exfil}"
    except Exception as e:
        error = f"Database Error: {e}"
    return render_template('c2_level1.html', result=result, error=error, flag=flag, pid=product_id)

@app.route('/challenge/2/level2')
def c2_level2():
    product_id = request.args.get('id', '1')
    result = error = flag = None
    # "Validación" numérica débil que puede bypassearse
    if product_id.isdigit():
        try:
            db = sqlite3.connect(DATABASE)
            cur = db.cursor()
            query = f"SELECT * FROM products WHERE id={product_id}"
            cur.execute(query)
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description] if cur.description else []
            db.close()
            result = [dict(zip(cols, r)) for r in rows]
            if any('FLAG' in str(r) for r in rows):
                flag = "FLAG{2B_un10n_s3lect_s3cret_t4ble}"
        except Exception as e:
            error = f"Error: {e}"
    else:
        # El truco: si contiene un espacio, puede llevar UNION (ej: "1 UNION...")
        try:
            db = sqlite3.connect(DATABASE)
            cur = db.cursor()
            query = f"SELECT * FROM products WHERE id={product_id}"
            cur.execute(query)
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description] if cur.description else []
            db.close()
            result = [dict(zip(cols, r)) for r in rows]
            if any('FLAG' in str(r) for r in rows):
                flag = "FLAG{2B_un10n_s3lect_s3cret_t4ble}"
        except Exception as e:
            error = f"Error: {e}"
    return render_template('c2_level2.html', result=result, error=error, flag=flag, pid=product_id)

# ═══════════════════════════════════════════════════════════════
# CHALLENGE 3 – UNION-Based SQLi (columnas)
#   FLAG_3A (Nivel 1 – UNION directo)
#   FLAG_3B (Nivel 2 – comentario inline necesario)
# ═══════════════════════════════════════════════════════════════

@app.route('/challenge/3')
def challenge3():
    return render_template('challenge3.html')

@app.route('/challenge/3/level1')
def c3_level1():
    search = request.args.get('q', '')
    result = error = flag = None
    try:
        db = sqlite3.connect(DATABASE)
        cur = db.cursor()
        query = f"SELECT id, name, category FROM products WHERE category='{search}'"
        cur.execute(query)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        db.close()
        result = [dict(zip(cols, r)) for r in rows]
        if any('FLAG' in str(r) for r in rows):
            flag = "FLAG{3A_un10n_s3lect_3cols_nailed}"
    except Exception as e:
        error = f"SQL Error: {e}"
    return render_template('c3_level1.html', result=result, error=error, flag=flag, q=search)

@app.route('/challenge/3/level2')
def c3_level2():
    search = request.args.get('q', '')
    result = error = flag = None
    # Filtra comillas simples pero no comentarios --
    sanitized = search.replace("'", "''")
    # Aún vulnerable a inyección sin comillas simples (numéricas) si q es int-like
    try:
        db = sqlite3.connect(DATABASE)
        cur = db.cursor()
        query = f"SELECT id, name, category FROM products WHERE category='{sanitized}' ORDER BY id"
        cur.execute(query)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        db.close()
        result = [dict(zip(cols, r)) for r in rows]
        if any('FLAG' in str(r) for r in rows):
            flag = "FLAG{3B_qu0te_escape_bypass_via_enc0ding}"
    except Exception as e:
        error = f"SQL Error: {e}"
    return render_template('c3_level2.html', result=result, error=error, flag=flag, q=search)

# ═══════════════════════════════════════════════════════════════
# CHALLENGE 4 – Blind Boolean SQLi
#   FLAG_4A (Nivel 1 – respuesta binaria visible)
#   FLAG_4B (Nivel 2 – respuesta genérica, necesita inferencia)
# ═══════════════════════════════════════════════════════════════

@app.route('/challenge/4')
def challenge4():
    return render_template('challenge4.html')

@app.route('/challenge/4/level1')
def c4_level1():
    user_id = request.args.get('id', '1')
    exists = flag = None
    try:
        db = sqlite3.connect(DATABASE)
        cur = db.cursor()
        query = f"SELECT id FROM users WHERE id={user_id}"
        cur.execute(query)
        row = cur.fetchone()
        db.close()
        exists = row is not None
        if exists and 'AND' in user_id.upper() and 'FLAG' in user_id.upper():
            flag = "FLAG{4A_bl1nd_bool_sqli_tr00}"
        elif exists:
            pass
    except Exception as e:
        exists = False
    return render_template('c4_level1.html', exists=exists, flag=flag, uid=user_id)

@app.route('/challenge/4/level2')
def c4_level2():
    user_id = request.args.get('id', '1')
    # Respuesta siempre genérica: solo "OK" o sin respuesta
    status = flag = None
    try:
        db = sqlite3.connect(DATABASE)
        cur = db.cursor()
        query = f"SELECT id FROM users WHERE id={user_id}"
        cur.execute(query)
        row = cur.fetchone()
        db.close()
        status = "exists" if row else "not_found"
        if status == "exists":
            flag = "FLAG{4B_bl1nd_b00l_t1me_b4sed}"
    except:
        status = "not_found"
    return render_template('c4_level2.html', status=status, flag=flag, uid=user_id)

# ═══════════════════════════════════════════════════════════════
# CHALLENGE 5 – SQLi en Search / Búsqueda avanzada
#   FLAG_5A (Nivel 1 – campo de búsqueda sin sanitizar)
#   FLAG_5B (Nivel 2 – limit/offset injection)
# ═══════════════════════════════════════════════════════════════

@app.route('/challenge/5')
def challenge5():
    return render_template('challenge5.html')

@app.route('/challenge/5/level1')
def c5_level1():
    q = request.args.get('search', '')
    result = error = flag = None
    try:
        db = sqlite3.connect(DATABASE)
        cur = db.cursor()
        query = f"SELECT id, name, description, price FROM products WHERE name LIKE '%{q}%'"
        cur.execute(query)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        db.close()
        result = [dict(zip(cols, r)) for r in rows]
        if any('FLAG' in str(r) for r in rows):
            flag = "FLAG{5A_lik3_cl4us3_sqli_pwned}"
    except Exception as e:
        error = str(e)
    return render_template('c5_level1.html', result=result, error=error, flag=flag, q=q)

@app.route('/challenge/5/level2')
def c5_level2():
    q = request.args.get('search', '')
    limit = request.args.get('limit', '5')
    result = error = flag = None
    # Sanitiza el search pero no el limit
    safe_q = q.replace("'", "''").replace('"', '""')
    try:
        db = sqlite3.connect(DATABASE)
        cur = db.cursor()
        query = f"SELECT id, name, description, price FROM products WHERE name LIKE '%{safe_q}%' LIMIT {limit}"
        cur.execute(query)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        db.close()
        result = [dict(zip(cols, r)) for r in rows]
        if any('FLAG' in str(r) for r in rows):
            flag = "FLAG{5B_l1m1t_param_sqli_bypass}"
    except Exception as e:
        error = str(e)
    return render_template('c5_level2.html', result=result, error=error, flag=flag, q=q, limit=limit)

# ═══════════════════════════════════════════════════════════════
# CHALLENGE 6 – SQLi en panel de administración / ORDER BY
#   FLAG_6A (Nivel 1 – ORDER BY injection)
#   FLAG_6B (Nivel 2 – segunda consulta / stacked-like con subquery)
# ═══════════════════════════════════════════════════════════════

@app.route('/challenge/6')
def challenge6():
    return render_template('challenge6.html')

@app.route('/challenge/6/level1')
def c6_level1():
    sort = request.args.get('sort', 'id')
    result = error = flag = None
    try:
        db = sqlite3.connect(DATABASE)
        cur = db.cursor()
        query = f"SELECT id, name, category, price FROM products ORDER BY {sort}"
        cur.execute(query)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        db.close()
        result = [dict(zip(cols, r)) for r in rows]
        if any('FLAG' in str(r) for r in rows):
            flag = "FLAG{6A_0rder_by_sqli_c4se_when}"
    except Exception as e:
        error = str(e)
    return render_template('c6_level1.html', result=result, error=error, flag=flag, sort=sort)

@app.route('/challenge/6/level2')
def c6_level2():
    sort = request.args.get('sort', 'id')
    col  = request.args.get('col', 'name')
    result = error = flag = None
    # Valida sort contra lista pero col es libre
    allowed_sorts = ['id', 'name', 'price', 'category']
    safe_sort = sort if sort in allowed_sorts else 'id'
    try:
        db = sqlite3.connect(DATABASE)
        cur = db.cursor()
        query = f"SELECT id, {col}, category, price FROM products ORDER BY {safe_sort}"
        cur.execute(query)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        db.close()
        result = [dict(zip(cols, r)) for r in rows]
        if any('FLAG' in str(r) for r in rows):
            flag = "FLAG{6B_c0l_inject_subquery_m4ster}"
    except Exception as e:
        error = str(e)
    return render_template('c6_level2.html', result=result, error=error, flag=flag, sort=sort, col=col)

# ─────────────────────────────────────────────
# Scoreboard
# ─────────────────────────────────────────────
@app.route('/scoreboard')
def scoreboard():
    flags = {
        "FLAG{1A_4dm1n_bypass_sqli_b4sic}":      "C1 Nivel 1 – Login Bypass básico",
        "FLAG{1B_w4f_bypass_case_OR_1=1}":        "C1 Nivel 2 – WAF Bypass (case)",
        "FLAG{2A_err0r_based_data_exfil}":        "C2 Nivel 1 – Error-Based Exfil",
        "FLAG{2B_un10n_s3lect_s3cret_t4ble}":     "C2 Nivel 2 – UNION Secret Table",
        "FLAG{3A_un10n_s3lect_3cols_nailed}":     "C3 Nivel 1 – UNION 3 columnas",
        "FLAG{3B_qu0te_escape_bypass_via_enc0ding}": "C3 Nivel 2 – Quote Escape Bypass",
        "FLAG{4A_bl1nd_bool_sqli_tr00}":          "C4 Nivel 1 – Blind Boolean",
        "FLAG{4B_bl1nd_b00l_t1me_b4sed}":         "C4 Nivel 2 – Blind Time-Based",
        "FLAG{5A_lik3_cl4us3_sqli_pwned}":        "C5 Nivel 1 – LIKE Clause SQLi",
        "FLAG{5B_l1m1t_param_sqli_bypass}":       "C5 Nivel 2 – LIMIT Param Bypass",
        "FLAG{6A_0rder_by_sqli_c4se_when}":       "C6 Nivel 1 – ORDER BY CASE/WHEN",
        "FLAG{6B_c0l_subquery_m4ster}": "C6 Nivel 2 – Column Subquery Inject",
    }
    return render_template('scoreboard.html', flags=flags)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
