import sqlite3
import hashlib

DB = 'vulnerable.db'

conn = sqlite3.connect(DB)
cur = conn.cursor()

# ── Tabla de usuarios ──────────────────────────────
cur.execute("DROP TABLE IF EXISTS users")
cur.execute("""
CREATE TABLE users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    role     TEXT DEFAULT 'user',
    email    TEXT,
    secret   TEXT
)
""")

users = [
    ('admin',    'admin123',                  'admin', 'admin@vulnmachine.local',  'FLAG{1A_4dm1n_bypass_sqli_b4sic}'),
    ('juan',     'password1',                 'user',  'juan@vulnmachine.local',   'nothing_here'),
    ('maria',    'qwerty2024',                'user',  'maria@vulnmachine.local',  'nothing_here'),
    ('root',     'toor',                      'admin', 'root@vulnmachine.local',   'FLAG{1B_w4f_bypass_case_OR_1=1}'),
    ('carlos',   'carlos123',                 'user',  'carlos@vulnmachine.local', 'nothing_here'),
    ('superuser','sup3rS3cur3!',              'admin', 'su@vulnmachine.local',     'FLAG{4A_bl1nd_bool_sqli_tr00}'),
    ('guest',    'guest',                     'guest', 'guest@vulnmachine.local',  'FLAG{4B_bl1nd_b00l_t1me_b4sed}'),
]
cur.executemany("INSERT INTO users (username, password, role, email, secret) VALUES (?,?,?,?,?)", users)

# ── Tabla de productos ─────────────────────────────
cur.execute("DROP TABLE IF EXISTS products")
cur.execute("""
CREATE TABLE products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    description TEXT,
    category    TEXT,
    price       REAL,
    stock       INTEGER,
    secret_flag TEXT
)
""")

products = [
    ('Laptop Pro X',    'Portátil de alta gama con 32GB RAM',         'Electronica', 1299.99, 15, 'nothing'),
    ('Mouse Inalámbrico','Ratón ergonómico 2.4GHz',                   'Accesorios',  29.99,   200, 'nothing'),
    ('Monitor 4K',      'Monitor UHD 27 pulgadas',                    'Electronica', 499.99,  40,  'FLAG{2A_err0r_based_data_exfil}'),
    ('Teclado Mecánico','Switches Cherry MX Red',                     'Accesorios',  89.99,   75,  'nothing'),
    ('Webcam HD',       'Cámara 1080p con micrófono',                 'Accesorios',  59.99,   120, 'nothing'),
    ('SSD 1TB',         'Disco sólido NVMe PCIe 4.0',                 'Almacenamiento', 99.99, 300, 'FLAG{2B_un10n_s3lect_s3cret_t4ble}'),
    ('RAM DDR5 32GB',   'Memoria de alta velocidad 6000MHz',          'Componentes', 149.99,  60,  'FLAG{3A_un10n_s3lect_3cols_nailed}'),
    ('GPU RTX 5090',    'Tarjeta gráfica de última generación',       'Componentes', 1999.99, 8,   'FLAG{3B_qu0te_escape_bypass_via_enc0ding}'),
    ('Router WiFi 7',   'Router tri-banda 10Gbps',                    'Redes',       199.99,  50,  'FLAG{5A_lik3_cl4us3_sqli_pwned}'),
    ('Switch 24p',      'Switch gestionable L2/L3',                   'Redes',       349.99,  20,  'FLAG{5B_l1m1t_param_sqli_bypass}'),
    ('NAS 4 bahías',    'Almacenamiento en red para empresas',        'Almacenamiento', 599.99, 12, 'FLAG{6A_0rder_by_sqli_c4se_when}'),
    ('UPS 1500VA',      'Sistema de alimentación ininterrumpida',     'Energia',     179.99,  35,  'FLAG{6B_c0l_subquery_m4ster}'),
]
cur.executemany("""
    INSERT INTO products (name, description, category, price, stock, secret_flag)
    VALUES (?,?,?,?,?,?)
""", products)

# ── Tabla secreta (bonus para UNION-based) ─────────
cur.execute("DROP TABLE IF EXISTS secret_flags")
cur.execute("""
CREATE TABLE secret_flags (
    id   INTEGER PRIMARY KEY,
    name TEXT,
    flag TEXT
)
""")
secrets = [
    (1, 'union_level1', 'FLAG{3A_un10n_s3lect_3cols_nailed}'),
    (2, 'union_level2', 'FLAG{3B_qu0te_escape_bypass_via_enc0ding}'),
    (3, 'hidden_bonus', 'FLAG{BONUS_sqlite_master_enum}'),
]
cur.executemany("INSERT INTO secret_flags VALUES (?,?,?)", secrets)

conn.commit()
conn.close()
print("✅ Base de datos 'vulnerable.db' creada correctamente.")
print("   Tablas: users, products, secret_flags")
