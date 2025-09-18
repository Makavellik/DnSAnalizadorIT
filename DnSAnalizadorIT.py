import dns.resolver
import dns.exception
import concurrent.futures
import logging
import socket
import requests
import json
from ipwhois import IPWhois
import ssl
import nmap
import time
from collections import defaultdict
from logging.handlers import RotatingFileHandler
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from ipaddress import ip_address
from rich import box
import hashlib
from datetime import datetime
import random
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeElapsedColumn, TextColumn
import pyfiglet
import random
import time
import os
import platform
from rich.text import Text
from pathlib import Path
import re
import idna

console = Console()

def detectar_entorno():
    sistema = platform.system()
    es_wsl = "microsoft" in platform.release().lower()
    es_docker = Path("/.dockerenv").exists() or os.path.exists("/.dockerinit")

    if es_docker:
        return "Docker"
    elif es_wsl:
        return "WSL"
    else:
        return sistema

def obtener_ip_local():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "No disponible"

def obtener_ip_publica():
    try:
        return requests.get("https://api.ipify.org", timeout=5).text
    except:
        return "No disponible"

def emoji_random():
    emojis = ["👁️", "🧠", "⚙️", "💀", "🕵️", "👽", "🧬", "🔮", "🛸", "🚨"]
    return random.choice(emojis)

def bcinematico(nombre="DARKCORE"):
    estilos = ["slant", "doom", "isometric1", "cybermedium", "speed", "rectangles"]
    ascii_art = pyfiglet.figlet_format(nombre, font=random.choice(estilos))

    try:
        os.system("cls" if os.name == "nt" else "clear")
    except:
        pass

    # Progreso de carga
    with Progress(
        SpinnerColumn(style="bold magenta"),
        TextColumn("[bold cyan]Inicializando núcleo de vigilancia...[/bold cyan]"),
        BarColumn(),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        tarea = progress.add_task("init", total=100)
        while not progress.finished:
            progress.update(tarea, advance=random.randint(3, 10))
            time.sleep(0.05)

    # Datos del sistema
    sistema = detectar_entorno()
    ip_local = obtener_ip_local()
    ip_publica = obtener_ip_publica()
    usuario = os.getenv("USER") or os.getenv("USERNAME") or "Desconocido"
    arquitectura = platform.machine()

    # Texto enriquecido
    texto = Text(ascii_art, style="bold red")
    texto += Text.from_markup(f"\n[bold green]>>> Acceso autorizado ✅ {emoji_random()}[/bold green]\n\n")
    texto += Text.from_markup(f"[bold cyan]🧠 Entorno:[/bold cyan] {sistema}\n")
    texto += Text.from_markup(f"[bold cyan]🕶️ Arquitectura:[/bold cyan] {arquitectura}\n")
    texto += Text.from_markup(f"[bold cyan]💡 Usuario:[/bold cyan] {usuario}\n")
    texto += Text.from_markup(f"[bold cyan]🌐 IP Local:[/bold cyan] {ip_local}\n")
    texto += Text.from_markup(f"[bold cyan]🚀 IP Pública:[/bold cyan] {ip_publica}\n\n")
    texto += Text.from_markup("[bold magenta]⚡ Modo Fantasma Activado - Sistema Invisible Operativo[/bold magenta]")

    panel = Panel(
        texto,
        title="[bold white on black]🧬 DARKCORE SYSTEM ONLINE 🧬[/bold white on black]",
        subtitle="[bold bright_black]↳ Interfaz de Dominación Activa[/bold bright_black]",
        border_style="bright_black",
        padding=(1, 4),
    )
    console.print(panel)

# --- Configuración avanzada de logging ---
def configurar_logging():
    formato_archivo = "%(asctime)s [%(levelname)s] (%(module)s:%(lineno)d): %(message)s"
    archivo_rotativo = RotatingFileHandler("dnsresulados.log", maxBytes=10*1024*1024, backupCount=5)
    archivo_rotativo.setLevel(logging.DEBUG)
    archivo_rotativo.setFormatter(logging.Formatter(formato_archivo))

    consola = logging.StreamHandler()
    consola.setLevel(logging.INFO)
    consola.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    logging.basicConfig(level=logging.DEBUG, handlers=[archivo_rotativo, consola])
    logging.info("Sistema de logging configurado correctamente.")

configurar_logging()

# --- WHOIS ---
def obtener_informacion_whois(ip):
    try:
        # Validación y clasificación de IP
        ip_obj = ip_address(ip)
        if ip_obj.is_private:
            console.print(Panel(f"[bold yellow]IP Privada Detectada:[/bold yellow] {ip}\n[dim]Escaneo omitido por seguridad.[/dim]", title="🔒 IP Privada", style="yellow"))
            return
        if ip_obj.is_loopback:
            console.print(Panel(f"[bold yellow]IP Localhost Detectada:[/bold yellow] {ip}\n[dim]No se realiza búsqueda WHOIS en 127.0.0.1[/dim]", title="🔁 IP Local", style="yellow"))
            return
        if ip_obj.is_reserved:
            console.print(Panel(f"[bold yellow]IP Reservada Detectada:[/bold yellow] {ip}\n[dim]Sin resultados disponibles en registros públicos.[/dim]", title="🛑 IP Reservada", style="yellow"))
            return

        # Lookup profundo WHOIS
        console.print(f"[cyan]🌍 Realizando consulta WHOIS para:[/cyan] {ip}")
        whois = IPWhois(ip)
        data = whois.lookup_rdap(depth=2)

        network = data.get("network", {})
        objects = data.get("objects", {})
        entities = data.get("entities", [])

        # Datos básicos
        nombre_red = network.get("name", "N/A")
        cidr = network.get("cidr", "N/A")
        pais = network.get("country", "N/A")
        inicio = network.get("start_address", "N/A")
        fin = network.get("end_address", "N/A")

        # Remarks y descripción (formateo múltiple)
        descripcion = "N/A"
        if remarks := network.get("remarks"):
            for r in remarks:
                desc = r.get("description")
                if isinstance(desc, list):
                    descripcion = " ".join(desc)
                    break

        # Titular, contacto, roles
        titular = email = org = estado = roles = "N/A"
        for obj_id, obj_data in objects.items():
            contacto = obj_data.get("contact", {})
            if not contacto:
                continue
            titular = contacto.get("name") or "N/A"
            email = contacto.get("email") or "N/A"
            org = obj_data.get("roles", ["N/A"])
            roles = ", ".join(org)
            estado = contacto.get("address", {}).get("value", "N/A") if isinstance(contacto.get("address"), dict) else "N/A"
            break

        tabla = Table(title="📄 WHOIS INFO DETALLADA", box=box.SIMPLE_HEAVY, border_style="cyan", show_lines=True)
        tabla.add_column("Campo", style="bold green", justify="right")
        tabla.add_column("Valor", style="white")

        tabla.add_row("IP", ip)
        tabla.add_row("Nombre Red", nombre_red)
        tabla.add_row("Rango IP", f"{inicio} - {fin}")
        tabla.add_row("CIDR", cidr)
        tabla.add_row("País", pais)
        tabla.add_row("Titular", titular)
        tabla.add_row("Email", email)
        tabla.add_row("Estado/Dirección", estado)
        tabla.add_row("Roles", roles)
        tabla.add_row("Descripción", descripcion)

        console.print(tabla)

        return data

    except Exception as e:
        console.print(Panel(f"[red]❌ Error al consultar WHOIS para {ip}:[/red] {e}", title="⚠️ WHOIS ERROR", style="red"))
        logging.error(f"Error WHOIS {ip}: {e}")


# --- Geolocalización ---
def geolocalizar_ip(ip):
    try:
        ip_obj = ip_address(ip)
        if ip_obj.is_private:
            console.print(Panel(
                f"[bold yellow]IP privada detectada:[/bold yellow] {ip}\n[dim]Geolocalización omitida.[/dim]",
                title="🔒 IP Privada", style="yellow"))
            return
        if ip_obj.is_loopback:
            console.print(Panel(
                f"[bold yellow]IP localhost detectada:[/bold yellow] {ip}\n[dim]Sin datos públicos disponibles.[/dim]",
                title="🔁 IP Local", style="yellow"))
            return
        if ip_obj.is_reserved:
            console.print(Panel(
                f"[bold yellow]IP reservada detectada:[/bold yellow] {ip}\n[dim]Sin resultados disponibles.[/dim]",
                title="🛑 IP Reservada", style="yellow"))
            return

        # Fuente principal: ipinfo.io
        headers = {'Accept': 'application/json'}
        res = requests.get(f"https://ipinfo.io/{ip}/json", headers=headers, timeout=5)
        if res.status_code != 200:
            raise Exception("Fallo en ipinfo, cambiando a ip-api")

        data = res.json()
        ciudad = data.get('city', 'N/A')
        region = data.get('region', 'N/A')
        pais = data.get('country', 'N/A')
        loc = data.get('loc', 'N/A')
        postal = data.get('postal', 'N/A')
        org = data.get('org', 'N/A')
        timezone = data.get('timezone', 'N/A')
        asn = data.get('asn', {}).get('asn') if isinstance(data.get('asn'), dict) else "N/A"

    except Exception as e:
        # Backup con ip-api.com
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=5)
            data = res.json()
            if data.get("status") != "success":
                raise Exception(data.get("message", "Error desconocido"))

            ciudad = data.get('city', 'N/A')
            region = data.get('regionName', 'N/A')
            pais = data.get('country', 'N/A')
            loc = f"{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}"
            postal = data.get('zip', 'N/A')
            org = data.get('org', 'N/A')
            timezone = data.get('timezone', 'N/A')
            asn = data.get('as', 'N/A')

        except Exception as fallback_error:
            console.print(Panel(f"[red]❌ No se pudo geolocalizar {ip}.[/red]\n[dim]{fallback_error}[/dim]",
                                title="🌐 Geolocalización Fallida", style="red"))
            logging.error(f"Geolocalización fallida para {ip}: {fallback_error}")
            return

    # Construcción del panel visual
    panel_texto = (
        f"[bold green]IP:[/bold green] {ip}\n"
        f"[bold cyan]Ciudad:[/bold cyan] {ciudad}\n"
        f"[bold cyan]Región:[/bold cyan] {region}\n"
        f"[bold cyan]País:[/bold cyan] {pais}\n"
        f"[bold cyan]Código Postal:[/bold cyan] {postal}\n"
        f"[bold cyan]Lat/Lon:[/bold cyan] {loc}\n"
        f"[bold cyan]Zona Horaria:[/bold cyan] {timezone}\n"
        f"[bold cyan]ASN:[/bold cyan] {asn}\n"
        f"[bold cyan]Proveedor:[/bold cyan] {org}"
    )

    console.print(Panel(panel_texto, title="🌍 Geolocalización Avanzada", box=box.DOUBLE, border_style="bright_blue"))
    return data  # Devuelve la data por si se quiere loguear, guardar o extender análisis


# --- Certificado SSL ---
def verificar_certificado_ssl(dominio, exportar_json=False):
    try:
        # 🚦 Paso 0: Validar accesibilidad
        try:
            socket.create_connection((dominio, 443), timeout=3).close()
        except Exception:
            console.print(Panel(
                f"[red]❌ El puerto 443 de {dominio} no está accesible.[/red]",
                title="🔌 Puerto Cerrado", style="red"))
            return

        contexto = ssl.create_default_context()
        with socket.create_connection((dominio, 443), timeout=5) as sock:
            with contexto.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert_bin = ssock.getpeercert(True)
                cert = ssock.getpeercert()
                protocolo_tls = ssock.version() or "Desconocido"

                # Emisor y sujeto
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))

                not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                dias_restantes = (not_after - datetime.utcnow()).days

                estado = "[green]✔ Válido[/green]" if dias_restantes > 0 else "[red]✘ Expirado[/red]"
                urgencia = ""
                if 0 < dias_restantes <= 30:
                    urgencia = "[yellow]⚠ Vence en menos de 30 días[/yellow]"

                # SAN (Subject Alternative Names)
                san = cert.get('subjectAltName', [])
                san_list = [s[1] for s in san if s[0] == 'DNS']
                san_text = "\n  - ".join(san_list) if san_list else "N/A"

                # CA y autofirmado
                ca_issuer = issuer.get('organizationName', 'N/A')
                auto_firmado = subject == issuer
                tipo_cert = "Auto-firmado" if auto_firmado else "Emitido por CA"

                # Fingerprints múltiples
                fingerprint_sha1 = hashlib.sha1(cert_bin).hexdigest().upper()
                fingerprint_sha256 = hashlib.sha256(cert_bin).hexdigest().upper()

                # Intento de extraer info extra (solo si está disponible)
                sig_alg = cert.get('signatureAlgorithm', 'N/D')
                version_cert = cert.get('version', 'N/D')

                # Panel visual quirúrgico
                panel_texto = (
                    f"[bold green]🌍 Dominio:[/bold green] {dominio}\n"
                    f"[cyan]🏢 Organización (Emisor):[/cyan] {ca_issuer}\n"
                    f"[cyan]👤 Emitido a:[/cyan] {subject.get('commonName', 'N/A')}\n"
                    f"[cyan]📜 Tipo de Certificado:[/cyan] {tipo_cert}\n\n"
                    f"[cyan]🔑 Versión TLS:[/cyan] {protocolo_tls}\n"
                    f"[cyan]🧬 Algoritmo de Firma:[/cyan] {sig_alg}\n"
                    f"[cyan]📂 Versión del Certificado:[/cyan] {version_cert}\n\n"
                    f"[cyan]📅 Válido desde:[/cyan] {not_before.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"[cyan]📅 Válido hasta:[/cyan] {not_after.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"[cyan]⏳ Días restantes:[/cyan] {dias_restantes} → {estado} {urgencia}\n\n"
                    f"[cyan]🔒 Fingerprint SHA-1:[/cyan] {fingerprint_sha1}\n"
                    f"[cyan]🔒 Fingerprint SHA-256:[/cyan] {fingerprint_sha256}\n\n"
                    f"[cyan]🌐 SAN (Nombres Alternativos):[/cyan]\n  - {san_text}"
                )

                console.print(Panel(panel_texto, title="🔐 Certificado SSL Quirúrgico", 
                                    box=box.DOUBLE_EDGE, border_style="bright_green"))

                # 📂 Exportación JSON opcional
                if exportar_json:
                    archivo = f"ssl_{dominio.replace('.', '_')}.json"
                    salida = {
                        "dominio": dominio,
                        "emisor": ca_issuer,
                        "emitido_a": subject,
                        "tipo_cert": tipo_cert,
                        "tls_version": protocolo_tls,
                        "algoritmo_firma": sig_alg,
                        "version_cert": version_cert,
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "dias_restantes": dias_restantes,
                        "estado": estado,
                        "fingerprint_sha1": fingerprint_sha1,
                        "fingerprint_sha256": fingerprint_sha256,
                        "san": san_list
                    }
                    with open(archivo, "w", encoding="utf-8") as f:
                        json.dump(salida, f, indent=4, ensure_ascii=False)
                    console.print(f"[blue]📄 Resultados exportados a [bold]{archivo}[/bold][/blue]")

    except ssl.SSLError as ssl_error:
        console.print(f"[red]⚠️ Error SSL al conectar con {dominio}:[/red] {ssl_error}")
        logging.error(f"SSL error en {dominio}: {ssl_error}")
    except socket.timeout:
        console.print(f"[red]⏱️ Tiempo de conexión agotado para {dominio}[/red]")
        logging.error(f"Timeout en conexión SSL con {dominio}")
    except Exception as e:
        console.print(f"[red]❌ Error inesperado al verificar SSL de {dominio}:[/red] {e}")
        logging.error(f"Error SSL inesperado en {dominio}: {e}")

# --- Consulta DNS ---
def consultar_registros(dominio, tipo_registro, resolver):
    try:
        return resolver.resolve(dominio, tipo_registro)
    except Exception:
        return []


def es_dominio_valido(dominio: str, detallado: bool = False):
    try:
        # Limpiar entradas comunes
        dominio = dominio.strip().lower()
        dominio = re.sub(r'^https?://', '', dominio)
        dominio = dominio.rstrip('/')

        # Verificar que no haya dobles puntos o errores comunes
        if ".." in dominio:
            return (False, "Dominio inválido: contiene '..'") if detallado else False

        # Convertir a formato IDNA si es internacionalizado (soporta acentos, emojis)
        try:
            dominio = idna.encode(dominio).decode('ascii')
        except idna.IDNAError:
            return (False, "Dominio internacionalizado inválido") if detallado else False

        # Expresión regular mejorada
        patron = r"^(?=.{1,253}$)(?!\-)([a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,63}$"
        valido = re.match(patron, dominio) is not None

        if detallado:
            return (valido, "OK" if valido else "No coincide con patrón DNS")
        else:
            return valido

    except Exception as e:
        return (False, f"Error inesperado: {e}") if detallado else False


def timestamp(utc=False, incluir_ms=False, formato=None, detallado=False):
    """
    Devuelve un timestamp en formato personalizado.

    Args:
        utc (bool): Si True, devuelve hora en UTC.
        incluir_ms (bool): Si True, incluye milisegundos.
        formato (str): Formato personalizado para strftime.
        detallado (bool): Si True, incluye nombre de día y zona horaria.

    Returns:
        str: Timestamp formateado.
    """
    try:
        ahora = datetime.utcnow() if utc else datetime.now()

        if not formato:
            formato = "[%Y-%m-%d %H:%M:%S"
            if incluir_ms:
                formato += ".%f"
            formato += "]"

        marca = ahora.strftime(formato)
        if incluir_ms:
            marca = marca[:-3] + "]"  # Truncar microsegundos a milisegundos

        if detallado:
            zona = "UTC" if utc else "Local"
            dia = ahora.strftime("%A")
            return f"{marca} ({dia}, {zona})"

        return marca

    except Exception as e:
        return f"[ERROR al generar timestamp: {e}]"


def registros_dns(dominio):
    tipos = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV']
    
    if not es_dominio_valido(dominio):
        console.print(f"[red]{timestamp()} ❌ Dominio no válido:[/red] {dominio}")
        return

    resolver = dns.resolver.Resolver()
    resolver.lifetime = resolver.timeout = 5.0

    console.rule(f"[bold magenta]🔎 {timestamp()} Consultando registros DNS para: {dominio}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tipos)) as executor:
        futures = {
            executor.submit(consultar_registros, dominio, tipo, resolver): tipo
            for tipo in tipos
        }

        for future in concurrent.futures.as_completed(futures):
            tipo = futures[future]
            try:
                respuestas = future.result()
                if not respuestas:
                    console.print(f"[yellow]{timestamp()} ⚠️ Sin resultados para {tipo}[/yellow]")
                    continue

                for respuesta in respuestas:
                    if tipo in ['A', 'AAAA']:
                        ip = respuesta.address
                        console.print(f"[blue]{timestamp()} {tipo}[/blue] => {ip}")
                        geolocalizar_ip(ip)
                        obtener_informacion_whois(ip)
                    elif tipo == 'CNAME':
                        console.print(f"[cyan]{timestamp()} CNAME[/cyan] => {respuesta.target}")
                    elif tipo == 'MX':
                        console.print(f"[cyan]{timestamp()} MX[/cyan] => {respuesta.exchange} (Prioridad {respuesta.preference})")
                    elif tipo == 'TXT':
                        txt = ' '.join(
                            s.decode('utf-8', errors='replace') if isinstance(s, bytes) else str(s)
                            for s in respuesta.strings
                        )
                        console.print(f"[cyan]{timestamp()} TXT[/cyan] => {txt}")
                    elif tipo == 'NS':
                        console.print(f"[cyan]{timestamp()} NS[/cyan] => {respuesta.target}")
                    elif tipo == 'SOA':
                        console.print(f"[cyan]{timestamp()} SOA[/cyan] => MName: {respuesta.mname}, Serial: {respuesta.serial}")
                    elif tipo == 'SRV':
                        console.print(f"[cyan]{timestamp()} SRV[/cyan] => {respuesta.target}:{respuesta.port}")
            except Exception as e:
                console.print(f"[red]{timestamp()} ❌ Error al consultar {tipo}: {e}[/red]")

    # Consultar el certificado SSL después del análisis DNS
    try:
        verificar_certificado_ssl(dominio)
    except Exception as e:
        console.print(f"[red]{timestamp()} ❌ Error al verificar certificado SSL: {e}[/red]")



# --- Evasión de detección DNS ---
def evasion_dns_multiservidor(dominio, registros_custom=None, exportar_json=False, comparar_tipos=("A",)):
    servidores = [
        "1.1.1.1", "1.0.0.1",         # Cloudflare
        "8.8.8.8", "8.8.4.4",         # Google
        "9.9.9.9", "149.112.112.112", # Quad9
        "208.67.222.222", "208.67.220.220", # OpenDNS
        "185.228.168.9", "64.6.64.6", # CleanBrowsing y Verisign
        "94.140.14.14",               # AdGuard
        "76.76.2.0",                  # Control D
    ]

    tipos_registros = registros_custom or ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'NS', 'SOA']
    resultados = defaultdict(lambda: defaultdict(list))
    tiempos, errores, inconsistencias = {}, {}, defaultdict(list)

    def validar_dns(srv):
        try:
            with socket.create_connection((srv, 53), timeout=2):
                return True
        except Exception:
            return False

    def fingerprint(data_list):
        if not data_list:
            return "VACÍO"
        data_str = "|".join(sorted(set(data_list)))
        return hashlib.sha256(data_str.encode()).hexdigest()[:12].upper()

    def consulta(srv, dom):
        # Jitter evasivo
        time.sleep(random.uniform(0.05, 0.3))
        inicio = time.time()
        respuesta_servidor = {}
        try:
            res = dns.resolver.Resolver()
            res.nameservers = [srv]
            res.lifetime = random.uniform(2.5, 4.5)
            res.timeout = res.lifetime

            for tipo in tipos_registros:
                try:
                    registros = res.resolve(dom, tipo, raise_on_no_answer=False)
                    if registros.rrset:
                        valores = [str(r.to_text()) for r in registros]
                        respuesta_servidor[tipo] = valores
                except dns.resolver.NoAnswer:
                    continue
                except Exception as e:
                    respuesta_servidor[tipo] = [f"❌ {str(e)}"]

            tiempos[srv] = round(time.time() - inicio, 3)
        except Exception as e:
            errores[srv] = str(e)
            return srv, {"Error": [f"❌ {str(e)}"]}
        return srv, respuesta_servidor

    # Validar servidores antes de consultas
    servidores_validos = [s for s in servidores if validar_dns(s)]
    if not servidores_validos:
        console.print("[red bold]❌ Ningún servidor DNS válido.[/red bold]")
        return

    random.shuffle(servidores_validos)  # Obfuscación
    max_workers = min(10, len(servidores_validos))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(consulta, srv, dominio): srv for srv in servidores_validos}
        for future in concurrent.futures.as_completed(futures):
            servidor, resultado = future.result()
            for tipo, valores in resultado.items():
                resultados[servidor][tipo] = valores

    # Comparar fingerprints de registros críticos
    fingerprints_base = {}
    for tipo in comparar_tipos:
        for srv, datos in resultados.items():
            if tipo in datos and datos[tipo]:
                fingerprints_base[tipo] = fingerprint(datos[tipo])
                break

    for tipo in comparar_tipos:
        base_fp = fingerprints_base.get(tipo)
        if not base_fp:
            continue
        for srv, datos in resultados.items():
            if tipo in datos and datos[tipo]:
                current_fp = fingerprint(datos[tipo])
                if current_fp != base_fp:
                    inconsistencias[srv].append(f"⚠ Diferencia en {tipo}")

    # Tabla de resultados
    table = Table(title=f"🛡️ Análisis DNS Multiservidor - {dominio}", box=box.SQUARE)
    table.add_column("DNS", style="bold cyan", no_wrap=True)
    table.add_column("Respuesta", style="green")
    table.add_column("Tiempo (s)", style="magenta", justify="center")

    for srv in resultados:
        respuesta = "\n".join(
            f"[yellow]{tipo}[/yellow]: {', '.join(valores)}"
            for tipo, valores in resultados[srv].items()
        ) or "[red]Sin respuesta[/red]"
        if srv in inconsistencias:
            respuesta += f"\n[red]{' | '.join(inconsistencias[srv])}[/red]"
        tiempo = str(tiempos.get(srv, "N/A"))
        table.add_row(srv, respuesta, tiempo)

    console.print(table)

    # Reportes
    if errores:
        console.print(f"\n[red bold]{timestamp()} ❌ Errores encontrados:[/red bold]")
        for srv, err in errores.items():
            console.print(f" - {srv}: {err}")

    if inconsistencias:
        console.print(f"\n[red bold]{timestamp()} ⚠️ Inconsistencias DNS detectadas:[/red bold]")
        for srv, issues in inconsistencias.items():
            for issue in issues:
                console.print(f" - {srv}: {issue}")
    else:
        console.print(f"\n[green bold]{timestamp()} ✅ Sin inconsistencias detectadas.[/green bold]")

    # Exportar JSON más detallado
    if exportar_json:
        resultado_json = {
            "dominio": dominio,
            "timestamp": timestamp(),
            "servidores_consultados": servidores_validos,
            "resultados": resultados,
            "tiempos": tiempos,
            "errores": errores,
            "inconsistencias": inconsistencias,
            "fingerprints": {t: fingerprints_base.get(t, None) for t in comparar_tipos}
        }
        fname = f"dns_{dominio.replace('.', '_')}.json"
        with open(fname, "w") as f:
            json.dump(resultado_json, f, indent=4)
        console.print(f"\n[blue]📄 Exportado a [bold]{fname}[/bold][/blue]")

# --- Escaneo de puertos con Nmap ---
def escanear_puertos(ip, puertos="1-1024", udp=False, detectar_vulnerabilidades=False, scripts_extra=None, verbose=True):
    escaner = nmap.PortScanner()
    argumentos_base = "-sV -O --reason --open"
    argumentos_tcp = "-sS"
    argumentos_udp = "-sU"
    
    # Construcción de argumentos dinámicos
    args = f"{argumentos_base} {argumentos_tcp}"
    if udp:
        args += f" {argumentos_udp}"
    if detectar_vulnerabilidades:
        args += " --script vuln,exploit"
    if scripts_extra:
        args += f" --script {scripts_extra}"

    console.rule(f"[bold magenta]🔍 Escaneando {ip}...")

    try:
        inicio_total = time.time()
        escaner.scan(ip, puertos, arguments=args)
        duracion_total = round(time.time() - inicio_total, 2)

        if not escaner.all_hosts():
            console.print(f"[red]❌ No se detectaron hosts activos en {ip}[/red]")
            return

        for host in escaner.all_hosts():
            hostname = escaner[host].hostname() or "Desconocido"
            mac = escaner[host]['addresses'].get('mac', 'N/D')
            os_detectado = "No detectado"
            if 'osmatch' in escaner[host] and escaner[host]['osmatch']:
                os_detectado = escaner[host]['osmatch'][0]['name']

            header = (
                f"[bold cyan]🎯 Host:[/bold cyan] {host} ({hostname})\n"
                f"[bold green]💽 MAC:[/bold green] {mac}\n"
                f"[bold blue]🧠 SO Detectado:[/bold blue] {os_detectado}\n"
                f"[bold yellow]⏱ Tiempo Total:[/bold yellow] {duracion_total}s"
            )
            console.print(Panel.fit(header, title="🧠 Análisis del Host", border_style="magenta"))

            for proto in escaner[host].all_protocols():
                puertos_proto = escaner[host][proto].keys()
                table = Table(title=f"📡 Puertos {proto.upper()}", box=box.SQUARE)
                table.add_column("Puerto", style="bold yellow", justify="center")
                table.add_column("Estado", style="bold", justify="center")
                table.add_column("Servicio", style="green", justify="center")
                table.add_column("Versión", style="magenta", justify="center")
                table.add_column("Info Extra", style="dim", justify="left")

                inicio_proto = time.time()

                for p in sorted(puertos_proto):
                    port_data = escaner[host][proto][p]
                    estado = port_data.get('state', 'unknown')
                    servicio = port_data.get('name', 'N/D')
                    version = port_data.get('version', '')
                    extra = port_data.get('extrainfo', '')
                    product = port_data.get('product', '')

                    color_estado = {
                        'open': '[green]ABIERTO[/green]',
                        'closed': '[red]CERRADO[/red]',
                        'filtered': '[yellow]FILTRADO[/yellow]'
                    }.get(estado, estado.upper())

                    table.add_row(str(p), color_estado, servicio or "N/D", version or product or "N/D", extra or "N/A")

                duracion_proto = round(time.time() - inicio_proto, 2)
                console.print(table)
                console.print(f"[italic]Duración para {proto.upper()}: {duracion_proto}s[/italic]\n")

    except Exception as e:
        logging.error(f"⚠️ Error al escanear {ip}: {e}")
        console.print(f"[bold red]❌ Error durante escaneo de {ip}:[/bold red] {e}")

# --- Interfaz interactiva ---
def menuprincipal():
    console.rule("[bold cyan]🧠 SISTEMA DE ANÁLISIS AVANZADO", style="cyan")
    console.print(Panel.fit(
        "[bold cyan]🔍 Analizador de Dominios y Escaneo de Puertos[/bold cyan]\n"
        "[white]Realiza consultas DNS avanzadas, evasión por múltiples servidores y escaneo selectivo de puertos.[/white]",
        title="[bold magenta]🎯 Interfaz Principal",
        subtitle="[dim]Escriba un dominio válido para comenzar...",
        border_style="bright_blue"
    ))

    while True:
        dominio = Prompt.ask("\n🔗 [bold]Ingrese un dominio o URL[/bold] (o escriba [red]'salir'[/red] para terminar)").strip()

        if dominio.lower() in ["salir", "exit", "q"]:
            console.print("\n[bold red]⛔ Sesión finalizada. Hasta luego.[/bold red]")
            break

        console.print(f"\n[bold yellow]📡 Analizando:[/bold yellow] {dominio}")

        try:
            registros_dns(dominio)
            evasion_dns_multiservidor(dominio)

            if Confirm.ask(f"\n🔐 ¿Desea escanear los puertos más comunes de [cyan]{dominio}[/cyan]?", default=True):
                ip = socket.gethostbyname(dominio)
                console.print(f"[green]✅ IP detectada:[/green] {ip}")
                escanear_puertos(ip, puertos="80,443,21,22,25", detectar_vulnerabilidades=True)
            else:
                console.print("[bold dim]⏭️ Escaneo de puertos omitido.[/bold dim]")

        except socket.gaierror:
            console.print(f"[bold red]❌ Dominio inválido o no se pudo resolver: {dominio}[/bold red]")
        except Exception as e:
            console.print(f"[bold red]⚠️ Error inesperado:[/bold red] {e}")

        console.rule("[dim]🔁 Fin de análisis - Puede ingresar otro dominio o escribir 'salir'.")

if __name__ == "__main__":
    bcinematico("ByMakaveli")
    menuprincipal()


