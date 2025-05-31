## 🎯 Objetivos de la Herramienta

- Realizar consultas DNS en paralelo para múltiples tipos de registros.
- Obtener información WHOIS detallada de direcciones IP.
- Geolocalizar IPs con precisión (ciudad, país, ISP).
- Validar y visualizar certificados SSL.
- Consultar múltiples servidores DNS públicos y comparar resultados.
- Ejecutar escaneos de puertos TCP/UDP y posibles vulnerabilidades usando Nmap.
- Consolidar logs detallados y profesionales de cada ejecución.

---

## 🧩 Funcionalidades Detalladas

### 🔍 Resolución DNS Completa
Consulta los siguientes registros:
- **A / AAAA:** Dirección IPv4 / IPv6 del dominio.
- **MX:** Servidores de correo.
- **TXT:** Registros de verificación (como SPF, DKIM, etc).
- **NS:** Nameservers autoritativos.
- **CNAME:** Alias de dominio.
- **SOA / SRV:** Información administrativa y de servicios.

> Las consultas se ejecutan en paralelo para mejorar el rendimiento.

---

### 🌐 Consulta Multiservidor DNS
Consulta simultáneamente a servidores DNS como:
- **Cloudflare (1.1.1.1)**
- **Google DNS (8.8.8.8)**
- **Quad9 (9.9.9.9)**
- **OpenDNS, CleanBrowsing, Verisign...**

Esto permite:
- **Detectar censura o manipulación DNS**.
- **Comparar tiempos de respuesta y confiabilidad**.

---

### 🧬 WHOIS por IP
Obtiene la información registral de la IP, incluyendo:
- Nombre del ISP o entidad administradora.
- Datos RDAP relevantes.
- Ideal para identificar hosting o datacenter.

---

### 🌍 Geolocalización de IPs
Consulta `https://ipinfo.io` para:
- País y ciudad de la IP.
- Organización o proveedor de servicio (ISP).
- Información útil para análisis geográficos o detección de tráfico sospechoso.

---

### 🔒 Verificación de Certificados SSL
Se conecta al puerto 443 del dominio para extraer:
- **Emisor del certificado.**
- **Fechas de validez.**
- **Algoritmos y seguridad del canal.**

Perfecto para:
- Validar dominios empresariales.
- Detectar certificados vencidos o autofirmados.

---

### 📡 Escaneo de Puertos y Vulnerabilidades (Nmap)
Lanza un escaneo con Nmap para detectar:
- Puertos TCP y UDP abiertos.
- Servicios y versiones detectadas.
- Sistema operativo remoto (detección de fingerprinting).
- Scripts de detección de vulnerabilidades (`--script vuln, exploit`).

🌐Ideal para:
- Reconocimiento previo a un pentest.
- Evaluación de exposición pública.
- Identificación de servicios innecesarios o mal configurados.
- OSINT: obtención pública de información sobre dominios/IP.
- Monitoreo de infraestructura externa.
- Detección de inconsistencias DNS.
- Reconocimiento previo a pruebas de penetración.



🔐 Casos de Uso
Usuario	Aplicación
🧑‍💻 Pentester	Recolectar información antes de un test de intrusión.
🛰️ SysAdmin	Verificar configuración DNS y servicios en producción.
🧠 Analista OSINT	Trazar relaciones y atribución geográfica de dominios sospechosos.
🛡️ Blue Team / SOC	Evaluar exposición pública de sistemas corporativos.
🎓 Educador / Estudiante	Enseñar fundamentos de red, DNS y seguridad de forma práctica.

⚠️ Aviso Legal
Este script está destinado exclusivamente para uso educativo, corporativo y con consentimiento explícito del propietario de los sistemas.
El uso indebido puede violar leyes locales e internacionales.
