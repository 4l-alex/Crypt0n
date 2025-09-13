import discord
from discord.ext import commands, tasks
import os
from dotenv import load_dotenv
import aiohttp
import asyncio
import requests
import whois
import dns.resolver
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import hashlib
import base64
import random
import string
import socket
import validators
from PIL import Image, ImageDraw
import io
import exiftool
import aiofiles
import sqlite3
from scapy.all import traceroute as scapy_traceroute
import subprocess
import json
import feedparser
from datetime import datetime, timedelta
from googletrans import Translator, LANGUAGES
import logging

# Configura logging
logging.basicConfig(filename='bot.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

# Carica variabili d'ambiente
load_dotenv()
TOKEN = os.getenv('tua_chiave')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'tua_chiave')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'tua_chiave')
HIBP_API_KEY = os.getenv('HIBP_API_KEY', 'tua_chiave')
OTX_API_KEY = os.getenv('OTX_API_KEY', 'tua_chiave')
IP_API_URL = 'http://ip-api.com/json/'

# Configura database SQLite
conn = sqlite3.connect('bot.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS monitors (url TEXT, hash TEXT, user_id INTEGER, frequency INTEGER)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS stats (command TEXT, count INTEGER)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS prefixes (guild_id INTEGER PRIMARY KEY, prefix TEXT)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS log_channels (guild_id INTEGER PRIMARY KEY, channel_id INTEGER)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS geoip_cache (ip TEXT PRIMARY KEY, data TEXT)''')
conn.commit()

# Bot personalizzato
class CustomBot(commands.Bot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.translator = Translator()
        self.languages = {}  # Lingua per utente
        self.encryption_keys = {}  # Temporaneo per encrypt/decrypt
        self.antiraid_enabled = {}
        self.join_times = {}
        self.prefixes = {}

    async def get_prefix(self, message):
        guild_id = message.guild.id if message.guild else 0
        return self.prefixes.get(guild_id, '$')

    async def send_translated(self, ctx, message):
        lang = self.languages.get(ctx.author.id, 'it')
        if lang != 'it':
            try:
                translated = self.translator.translate(message, dest=lang).text
                await ctx.send(translated)
            except Exception as e:
                logging.error(f"Errore traduzione: {e}")
                await ctx.send(message)
        else:
            await ctx.send(message)

# Definisci il bot
bot = CustomBot(command_prefix=lambda bot, msg: bot.get_prefix(msg), intents=discord.Intents.all())

# Rimuovi il comando $help predefinito
bot.remove_command('help')

# Carica prefissi
cursor.execute('SELECT * FROM prefixes')
for row in cursor.fetchall():
    bot.prefixes[row[0]] = row[1]

# Evento: Bot pronto
@bot.event
async def on_ready():
    logging.info(f'Connesso come {bot.user.name}')
    await bot.change_presence(activity=discord.Game(name="Crypt0n v2.1 | Sicurezza Multilingua"))
    monitor_changes.start()

# Evento: Antiraid
@bot.event
async def on_member_join(member):
    guild_id = member.guild.id
    if bot.antiraid_enabled.get(guild_id, False):
        now = datetime.now()
        if guild_id not in bot.join_times:
            bot.join_times[guild_id] = []
        bot.join_times[guild_id] = [t for t in bot.join_times[guild_id] if now - t < timedelta(minutes=1)]
        bot.join_times[guild_id].append(now)
        if len(bot.join_times[guild_id]) > 10:
            await member.ban(reason="Raid detectato")
            cursor.execute('SELECT channel_id FROM log_channels WHERE guild_id = ?', (guild_id,))
            row = cursor.fetchone()
            if row:
                channel = bot.get_channel(row[0])
                await bot.send_translated(channel, f"Raid detectato: {member} bannato automaticamente.")
            logging.warning(f"Raid detectato in {guild_id}: {member}")

# Task monitoraggio
@tasks.loop(minutes=1)
async def monitor_changes():
    cursor.execute('SELECT * FROM monitors')
    for row in cursor.fetchall():
        url, old_hash, user_id, freq = row
        if (datetime.now() - datetime.now()) % timedelta(minutes=freq) == timedelta(0):  # Semplificato
            try:
                response = requests.get(url)
                new_hash = hashlib.md5(response.content).hexdigest()
                if new_hash != old_hash:
                    user = await bot.fetch_user(user_id)
                    await bot.send_translated(user, f"Cambiamento rilevato su {url}!")
                    cursor.execute('UPDATE monitors SET hash = ? WHERE url = ?', (new_hash, url))
                    conn.commit()
            except Exception as e:
                logging.error(f"Errore monitoraggio {url}: {e}")

# Update stats
def update_stats(command):
    cursor.execute('SELECT count FROM stats WHERE command = ?', (command,))
    row = cursor.fetchone()
    if row:
        cursor.execute('UPDATE stats SET count = ? WHERE command = ?', (row[0] + 1, command))
    else:
        cursor.execute('INSERT INTO stats VALUES (?, 1)', (command,))
    conn.commit()

# Cog Analisi Avanzata
class AnalisiAvanzata(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def traceroute(self, ctx, target: str):
        update_stats('traceroute')
        try:
            ans, unans = scapy_traceroute(target)
            result = "\n".join([f"Hop {hop}: {addr}" for hop, addr in ans.res])
            await self.bot.send_translated(ctx, f"Traceroute per {target}:\n{result}")
        except Exception as e:
            try:
                result = subprocess.getoutput(f'traceroute {target}')
                await self.bot.send_translated(ctx, f"Traceroute (fallback) per {target}:\n{result}")
            except:
                await self.bot.send_translated(ctx, f"Errore: {str(e)}. Assicurati di avere Npcap/libpcap installato.")

    @commands.command()
    async def sslcheck(self, ctx, domain: str):
        update_stats('sslcheck')
        try:
            import ssl
            cert = ssl.get_server_certificate((domain, 443))
            await self.bot.send_translated(ctx, f"Certificato SSL per {domain}:\n{cert[:500]}...")
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def subdomains(self, ctx, domain: str):
        update_stats('subdomains')
        common_subs = ['www', 'mail', 'ftp', 'api', 'test', 'dev', 'blog']
        results = []
        for sub in common_subs:
            try:
                dns.resolver.resolve(f"{sub}.{domain}", 'A')
                results.append(f"{sub}.{domain}")
            except:
                pass
        await self.bot.send_translated(ctx, f"Subdomini trovati per {domain}: {', '.join(results) or 'Nessuno'}")

    @commands.command()
    async def geoip(self, ctx, ip: str):
        update_stats('geoip')
        cursor.execute('SELECT data FROM geoip_cache WHERE ip = ?', (ip,))
        cached = cursor.fetchone()
        if cached:
            data = json.loads(cached[0])
            await self.bot.send_translated(ctx, f"GeoIP per {ip} (cache):\nCittà: {data['city']}\nPaese: {data['country']}\nISP: {data['isp']}")
            return
        try:
            response = requests.get(f"{IP_API_URL}{ip}")
            data = response.json()
            if data['status'] == 'success':
                cursor.execute('INSERT INTO geoip_cache (ip, data) VALUES (?, ?)', (ip, json.dumps(data)))
                conn.commit()
                await self.bot.send_translated(ctx, f"GeoIP per {ip}:\nCittà: {data['city']}\nPaese: {data['country']}\nISP: {data['isp']}")
            else:
                await self.bot.send_translated(ctx, "Errore nella ricerca.")
        except Exception as e:
            if response.status_code == 429:
                await self.bot.send_translated(ctx, "Limite di richieste superato. Riprova tra un minuto.")
            else:
                await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def webtech(self, ctx, url: str):
        update_stats('webtech')
        try:
            response = requests.get(url)
            headers = response.headers
            techs = []
            if 'server' in headers: techs.append(headers['server'])
            if 'x-powered-by' in headers: techs.append(headers['x-powered-by'])
            await self.bot.send_translated(ctx, f"Tecnologie rilevate per {url}: {', '.join(techs) or 'Nessuna'}")
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def robotstxt(self, ctx, domain: str):
        update_stats('robotstxt')
        try:
            response = requests.get(f"https://{domain}/robots.txt")
            await self.bot.send_translated(ctx, f"robots.txt per {domain}:\n{response.text[:1000]}...")
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

# Cog Analisi Forense
class AnalisiForense(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def filehash(self, ctx):
        update_stats('filehash')
        if not ctx.message.attachments:
            return await self.bot.send_translated(ctx, "Allega un file!")
        attachment = ctx.message.attachments[0]
        async with aiohttp.ClientSession() as session:
            async with session.get(attachment.url) as resp:
                content = await resp.read()
        hashes = {
            'md5': hashlib.md5(content).hexdigest(),
            'sha1': hashlib.sha1(content).hexdigest(),
            'sha256': hashlib.sha256(content).hexdigest()
        }
        await self.bot.send_translated(ctx, f"Hash multipli:\n{json.dumps(hashes, indent=2)}")

    @commands.command()
    async def integrity(self, ctx, expected_hash: str):
        update_stats('integrity')
        if not ctx.message.attachments:
            return await self.bot.send_translated(ctx, "Allega un file!")
        attachment = ctx.message.attachments[0]
        async with aiohttp.ClientSession() as session:
            async with session.get(attachment.url) as resp:
                content = await resp.read()
        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash == expected_hash:
            await self.bot.send_translated(ctx, "Integrità verificata!")
        else:
            await self.bot.send_translated(ctx, f"Integrità fallita! Hash atteso: {expected_hash}, Reale: {actual_hash}")

    @commands.command()
    async def multihash(self, ctx, *, text: str):
        update_stats('multihash')
        hashes = {
            'md5': hashlib.md5(text.encode()).hexdigest(),
            'sha1': hashlib.sha1(text.encode()).hexdigest(),
            'sha256': hashlib.sha256(text.encode()).hexdigest()
        }
        await self.bot.send_translated(ctx, f"Hash multipli per '{text}':\n{json.dumps(hashes, indent=2)}")

    @commands.command()
    async def rsagen(self, ctx, size: int = 2048):
        update_stats('rsagen')
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=size)
        public_key = private_key.public_key()
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        await self.bot.send_translated(ctx, f"Chiavi RSA ({size} bit):\n**Pubblica:**\n{pub_pem}\n**Privata:**\n{priv_pem}")

# Cog Intelligenza Minacce
class IntelligenzaMinacce(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def threatip(self, ctx, ip: str):
        update_stats('threatip')
        if not ABUSEIPDB_API_KEY:
            return await self.bot.send_translated(ctx, "Configura ABUSEIPDB_API_KEY!")
        headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
        data = response.json()
        score = data['data']['abuseConfidenceScore']
        msg = f"Analisi minaccia per {ip}:\nAbuse Confidence: {score}%"
        await self.bot.send_translated(ctx, msg)
        if score > 80:
            await ctx.author.send(f"⚠️ Allerta: {ip} ha un alto punteggio di rischio ({score}%)!")

    @commands.command()
    async def blacklist(self, ctx, target: str):
        update_stats('blacklist')
        await self.bot.send_translated(ctx, f"Verifica liste nere per {target}: (Placeholder - Integra API come Spamhaus)")
        # TODO: Aggiungi API

    @commands.command()
    async def threatfeed(self, ctx):
        update_stats('threatfeed')
        if not OTX_API_KEY:
            return await self.bot.send_translated(ctx, "Configura OTX_API_KEY!")
        url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit=5"
        headers = {'X-OTX-API-KEY': OTX_API_KEY}
        try:
            response = requests.get(url, headers=headers)
            data = response.json()
            feeds = "\n".join([p['name'] for p in data['results']])
            await self.bot.send_translated(ctx, f"Ultimi threat feed:\n{feeds}")
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

# Cog OSINT Avanzato
class OSINTAvanzato(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def socialsearch(self, ctx, username: str):
        update_stats('socialsearch')
        sites = ['twitter', 'instagram', 'facebook', 'github', 'linkedin']
        results = []
        for site in sites:
            url = f"https://www.{site}.com/{username}"
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    results.append(url)
            except:
                pass
        await self.bot.send_translated(ctx, f"Risultati OSINT per {username}: {', '.join(results) or 'Nessuno'}")

# Cog Monitoraggio
class Monitoraggio(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def monitor(self, ctx, url: str, freq: int = 5):
        update_stats('monitor')
        try:
            response = requests.get(url)
            page_hash = hashlib.md5(response.content).hexdigest()
            cursor.execute('INSERT INTO monitors VALUES (?, ?, ?, ?)', (url, page_hash, ctx.author.id, freq))
            conn.commit()
            await self.bot.send_translated(ctx, f"Monitoraggio avviato per {url} ogni {freq} minuti.")
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def stopmonitor(self, ctx, url: str):
        update_stats('stopmonitor')
        cursor.execute('DELETE FROM monitors WHERE url = ? AND user_id = ?', (url, ctx.author.id))
        conn.commit()
        await self.bot.send_translated(ctx, f"Monitoraggio fermato per {url}.")

    @commands.command()
    async def monitors(self, ctx):
        update_stats('monitors')
        cursor.execute('SELECT url, frequency FROM monitors WHERE user_id = ?', (ctx.author.id,))
        urls = [f"{row[0]} (ogni {row[1]} min)" for row in cursor.fetchall()]
        await self.bot.send_translated(ctx, f"I tuoi monitor: {', '.join(urls) or 'Nessuno'}")

    @commands.command()
    async def stats(self, ctx):
        update_stats('stats')
        cursor.execute('SELECT * FROM stats')
        stats = "\n".join([f"{cmd}: {count}" for cmd, count in cursor.fetchall()])
        await self.bot.send_translated(ctx, f"Statistiche bot:\n{stats or 'Nessune'}")

    @commands.command()
    async def report(self, ctx):
        update_stats('report')
        await self.bot.send_translated(ctx, "Report personale: (Placeholder - Aggiungi log utente)")

# Cog Comandi Base
class ComandiBase(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def ipinfo(self, ctx, ip: str):
        update_stats('ipinfo')
        try:
            response = requests.get(f"{IP_API_URL}{ip}")
            data = response.json()
            if data['status'] == 'success':
                await self.bot.send_translated(ctx, f"IP Info per {ip}:\nCittà: {data['city']}\nPaese: {data['country']}\nISP: {data['isp']}")
            else:
                await self.bot.send_translated(ctx, "Errore nella ricerca.")
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def dnslookup(self, ctx, domain: str):
        update_stats('dnslookup')
        try:
            ips = [str(ip) for ip in dns.resolver.resolve(domain, 'A')]
            await self.bot.send_translated(ctx, f"DNS per {domain}: {', '.join(ips)}")
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def whois(self, ctx, domain: str):
        update_stats('whois')
        try:
            w = whois.whois(domain)
            await self.bot.send_translated(ctx, f"WHOIS per {domain}:\nRegistrante: {w.name}\nEmail: {w.email}\nData: {w.creation_date}")
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def hash(self, ctx, algorithm: str, *, text: str):
        update_stats('hash')
        try:
            h = hashlib.new(algorithm)
            h.update(text.encode())
            await self.bot.send_translated(ctx, f"{algorithm.upper()} hash: {h.hexdigest()}")
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}. Algoritmi: md5, sha1, sha256, etc.")

    @commands.command()
    async def encode64(self, ctx, *, text: str):
        update_stats('encode64')
        encoded = base64.b64encode(text.encode()).decode()
        await self.bot.send_translated(ctx, f"Base64 encoded: {encoded}")

    @commands.command()
    async def decode64(self, ctx, *, encoded: str):
        update_stats('decode64')
        try:
            decoded = base64.b64decode(encoded).decode()
            await self.bot.send_translated(ctx, f"Base64 decoded: {decoded}")
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def genpassword(self, ctx, length: int = 12):
        update_stats('genpassword')
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(chars) for _ in range(length))
        await self.bot.send_translated(ctx, f"Password generata: {password}")

    @commands.command()
    async def headers(self, ctx, url: str):
        update_stats('headers')
        try:
            response = requests.get(url)
            headers = json.dumps(dict(response.headers), indent=2)
            await self.bot.send_translated(ctx, f"Header per {url}:\n{headers}")
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def checkemail(self, ctx, email: str):
        update_stats('checkemail')
        if validators.email(email):
            await self.bot.send_translated(ctx, f"{email} è valida.")
        else:
            await self.bot.send_translated(ctx, f"{email} non è valida.")

    @commands.command()
    async def portscan(self, ctx, ip: str, start: int = 1, end: int = 1024):
        update_stats('portscan')
        open_ports = []
        for port in range(start, min(end + 1, 1024)):  # Limite per evitare abusi
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        await self.bot.send_translated(ctx, f"Porte aperte su {ip}: {', '.join(map(str, open_ports)) or 'Nessuna'}")

    @commands.command()
    async def analyzeurl(self, ctx, url: str):
        update_stats('analyzeurl')
        if not VIRUSTOTAL_API_KEY:
            return await self.bot.send_translated(ctx, "Configura VIRUSTOTAL_API_KEY!")
        params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        data = response.json()
        if data['response_code'] == 1:
            await self.bot.send_translated(ctx, f"Analisi URL {url}: Positivi: {data['positives']}/{data['total']}")
        else:
            await self.bot.send_translated(ctx, "Nessuna analisi disponibile.")

    @commands.command()
    async def passwordstrength(self, ctx, password: str):
        update_stats('passwordstrength')
        strength = 0
        if len(password) >= 8: strength += 1
        if any(c.islower() for c in password): strength += 1
        if any(c.isupper() for c in password): strength += 1
        if any(c.isdigit() for c in password): strength += 1
        if any(c in string.punctuation for c in password): strength += 1
        levels = ['Molto Debole', 'Debole', 'Media', 'Forte', 'Molto Forte']
        await self.bot.send_translated(ctx, f"Forza password: {levels[strength - 1]} ({strength}/5)")

    @commands.command()
    async def cybernews(self, ctx):
        update_stats('cybernews')
        feed = feedparser.parse('https://krebsonsecurity.com/feed/')
        news = "\n".join([entry.title for entry in feed.entries[:5]])
        await self.bot.send_translated(ctx, f"Notizie cybersecurity:\n{news}")

    @commands.command()
    async def checkleak(self, ctx, query: str):
        update_stats('checkleak')
        if not HIBP_API_KEY:
            return await self.bot.send_translated(ctx, "HIBP API non configurata. Usa $checkleak_manual per alternative.")
        headers = {'hibp-api-key': HIBP_API_KEY, 'user-agent': 'Crypt0n-Bot'}
        response = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{query}', headers=headers)
        if response.status_code == 200:
            breaches = ", ".join([b['Name'] for b in response.json()])
            await self.bot.send_translated(ctx, f"Filtrazioni per {query}: {breaches}")
        else:
            await self.bot.send_translated(ctx, "Nessuna filtrazione trovata o errore.")

    @commands.command()
    async def checkleak_manual(self, ctx):
        update_stats('checkleak_manual')
        await self.bot.send_translated(ctx, "Verifica violazioni manualmente su https://haveibeenpwned.com")

    @commands.command()
    async def metadata(self, ctx):
        update_stats('metadata')
        if not ctx.message.attachments:
            return await self.bot.send_translated(ctx, "Allega un file!")
        attachment = ctx.message.attachments[0]
        if attachment.filename.endswith(('.jpg', '.png', '.tiff')):
            async with aiofiles.open('temp_file', 'wb') as f:
                await attachment.save(f.name)
            with exiftool.ExifTool() as et:
                metadata = et.get_metadata('temp_file')
            os.remove('temp_file')
            await self.bot.send_translated(ctx, f"Metadati:\n{json.dumps(metadata, indent=2)[:1000]}...")
        else:
            await self.bot.send_translated(ctx, "Supportato solo immagini.")

    @commands.command()
    async def encrypt(self, ctx, *, message: str):
        update_stats('encrypt')
        key = Fernet.generate_key()
        f = Fernet(key)
        encrypted = f.encrypt(message.encode())
        self.bot.encryption_keys[ctx.author.id] = key
        await self.bot.send_translated(ctx, f"Messaggio cifrato: {encrypted.decode()}\nChiave (salvala!): {key.decode()}")

    @commands.command()
    async def decrypt(self, ctx, *, encrypted: str):
        update_stats('decrypt')
        key = self.bot.encryption_keys.get(ctx.author.id)
        if not key:
            return await self.bot.send_translated(ctx, "Nessuna chiave trovata. Usa $encrypt o fornisci chiave.")
        f = Fernet(key)
        try:
            decrypted = f.decrypt(encrypted.encode()).decode()
            await self.bot.send_translated(ctx, f"Messaggio decifrato: {decrypted}")
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def scanfile(self, ctx):
        update_stats('scanfile')
        if not ctx.message.attachments:
            return await self.bot.send_translated(ctx, "Allega un file!")
        if not VIRUSTOTAL_API_KEY:
            return await self.bot.send_translated(ctx, "Configura VIRUSTOTAL_API_KEY!")
        attachment = ctx.message.attachments[0]
        params = {'apikey': VIRUSTOTAL_API_KEY}
        files = {'file': (attachment.filename, await attachment.read())}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        data = response.json()
        await self.bot.send_translated(ctx, f"Scan avviato: Resource {data['scan_id']}. Controlla dopo con API report.")

# Cog Moderazione
class Moderazione(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    @commands.has_permissions(ban_members=True)
    async def ban(self, ctx, member: discord.Member, *, reason: str = "Nessun motivo"):
        update_stats('ban')
        await member.ban(reason=reason)
        await self.bot.send_translated(ctx, f"{member} bannato per: {reason}")

    @commands.command()
    @commands.has_permissions(kick_members=True)
    async def kick(self, ctx, member: discord.Member, *, reason: str = "Nessun motivo"):
        update_stats('kick')
        await member.kick(reason=reason)
        await self.bot.send_translated(ctx, f"{member} espulso per: {reason}")

    @commands.command()
    @commands.has_permissions(administrator=True)
    async def antiraid(self, ctx, state: str):
        update_stats('antiraid')
        guild_id = ctx.guild.id
        if state.lower() == 'on':
            self.bot.antiraid_enabled[guild_id] = True
            await self.bot.send_translated(ctx, "Protezione antiraid attivata.")
        elif state.lower() == 'off':
            self.bot.antiraid_enabled[guild_id] = False
            await self.bot.send_translated(ctx, "Protezione antiraid disattivata.")
        else:
            await self.bot.send_translated(ctx, "Usa 'on' o 'off'.")

    @commands.command()
    @commands.has_permissions(administrator=True)
    async def setlogchannel(self, ctx, channel: discord.TextChannel):
        update_stats('setlogchannel')
        guild_id = ctx.guild.id
        cursor.execute('REPLACE INTO log_channels VALUES (?, ?)', (guild_id, channel.id))
        conn.commit()
        await self.bot.send_translated(ctx, f"Log channel impostato su {channel.name}.")

# Cog Utilità
class Utilita(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def setlanguage(self, ctx, lang: str):
        update_stats('setlanguage')
        if lang in LANGUAGES:
            self.bot.languages[ctx.author.id] = lang
            await self.bot.send_translated(ctx, f"Lingua impostata su {LANGUAGES[lang]} ({lang}).")
        else:
            await self.bot.send_translated(ctx, "Lingua non supportata. Usa codici come 'en', 'fr', 'hi', etc.")

    @commands.command()
    async def listlanguages(self, ctx):
        update_stats('listlanguages')
        langs = ", ".join([f"{code}: {name}" for code, name in list(LANGUAGES.items())[:50]])
        await self.bot.send_translated(ctx, f"Lingue supportate (prime 50): {langs}... (Totale: {len(LANGUAGES)})")

    @commands.command()
    async def translate(self, ctx, *, args: str):
        update_stats('translate')
        parts = args.split()
        if len(parts) < 2:
            return await self.bot.send_translated(ctx, "Usa: $translate [testo] [da_lingua opzionale] [a_lingua]")
        to_lang = parts[-1]
        from_lang = parts[-2] if len(parts) > 2 and len(parts[-2]) == 2 else None
        text = " ".join(parts[:-1 if from_lang else -2])
        try:
            translated = self.bot.translator.translate(text, src=from_lang or 'auto', dest=to_lang).text
            await self.bot.send_translated(ctx, f"Traduzione: {translated}")
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def setprefix(self, ctx, new_prefix: str):
        update_stats('setprefix')
        if ctx.guild:
            guild_id = ctx.guild.id
            self.bot.prefixes[guild_id] = new_prefix
            cursor.execute('REPLACE INTO prefixes VALUES (?, ?)', (guild_id, new_prefix))
            conn.commit()
            await self.bot.send_translated(ctx, f"Prefisso impostato su {new_prefix} per questo server.")
        else:
            await self.bot.send_translated(ctx, "Solo in server.")

    @commands.command()
    async def userinfo(self, ctx, member: discord.Member = None):
        update_stats('userinfo')
        member = member or ctx.author
        embed = discord.Embed(title=f"Informazioni su {member}", color=discord.Color.dark_blue())
        embed.add_field(name="ID", value=member.id)
        embed.add_field(name="Creato il", value=member.created_at)
        await ctx.send(embed=embed)

    @commands.command()
    async def serverinfo(self, ctx):
        update_stats('serverinfo')
        guild = ctx.guild
        embed = discord.Embed(title=f"Informazioni su {guild.name}", color=discord.Color.dark_blue())
        embed.add_field(name="Membri", value=guild.member_count)
        embed.add_field(name="Creato il", value=guild.created_at)
        await ctx.send(embed=embed)

    @commands.command()
    async def invite(self, ctx):
        update_stats('invite')
        await self.bot.send_translated(ctx, f"Invita il bot: {discord.utils.oauth_url(self.bot.user.id, permissions=discord.Permissions.all())}")

    @commands.command()
    async def avatar(self, ctx, member: discord.Member = None):
        update_stats('avatar')
        member = member or ctx.author
        async with aiohttp.ClientSession() as session:
            async with session.get(str(member.avatar.url)) as resp:
                img_data = await resp.read()
        with Image.open(io.BytesIO(img_data)) as img:
            img = img.resize((128, 128)).convert('RGB')
            draw = ImageDraw.Draw(img)
            draw.ellipse((0, 0, 128, 128), outline="blue", width=5)
            with io.BytesIO() as buffer:
                img.save(buffer, "PNG")
                buffer.seek(0)
                file = discord.File(buffer, filename="avatar.png")
                await ctx.send(file=file)

    @commands.command()
    async def credits(self, ctx):
        update_stats('credits')
        embed = discord.Embed(
            title="Crypt0n v2.1 - Crediti",
            description="Un bot avanzato per la sicurezza informatica con supporto multilingua.",
            color=discord.Color.dark_blue()
        )
        embed.add_field(name="Sviluppatori", value="Team Crypt0n", inline=False)
        embed.add_field(name="Versione", value="2.1 - Analisi e Protezione Avanzata", inline=True)
        embed.add_field(name="Supporto", value="[Server Discord](https://discord.gg/tuo_server)\n[GitHub](https://github.com/tuo_repo)", inline=True)
        embed.add_field(name="Ringraziamenti", value="Realizzato con discord.py, googletrans e il supporto di Grok (xAI).", inline=False)
        embed.set_footer(text=f"Crypt0n | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        embed.set_thumbnail(url="https://example.com/crypt0n_logo.png")
        await ctx.send(embed=embed)

    @commands.command()
    async def help(self, ctx):
        update_stats('help')
        embed = discord.Embed(title="Crypt0n - Elenco Comandi", description="Comandi disponibili, tradotti nella tua lingua.", color=discord.Color.dark_blue())
        embed.add_field(name="Analisi Avanzata", value="$traceroute, $sslcheck, $subdomains, $geoip, $webtech, $robotstxt", inline=False)
        embed.add_field(name="Analisi Forense", value="$filehash, $integrity, $multihash, $rsagen", inline=False)
        embed.add_field(name="Intelligenza Minacce", value="$threatip, $blacklist, $threatfeed", inline=False)
        embed.add_field(name="OSINT", value="$socialsearch", inline=False)
        embed.add_field(name="Monitoraggio", value="$monitor, $stopmonitor, $monitors, $stats, $report", inline=False)
        embed.add_field(name="Comandi Base", value="$ipinfo, $dnslookup, $whois, $hash, $encode64, $decode64, $genpassword, $headers, $checkemail, $portscan, $analyzeurl, $passwordstrength, $cybernews, $checkleak, $checkleak_manual, $metadata, $encrypt, $decrypt, $scanfile", inline=False)
        embed.add_field(name="Moderazione", value="$ban, $kick, $antiraid, $setlogchannel", inline=False)
        embed.add_field(name="Utilità", value="$setlanguage, $listlanguages, $translate, $setprefix, $userinfo, $serverinfo, $invite, $avatar, $credits, $help", inline=False)
        embed.set_footer(text=f"Crypt0n | Usa $credits per info | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        await ctx.send(embed=embed)

# Aggiungi cog
async def setup(bot):
    await bot.add_cog(AnalisiAvanzata(bot))
    await bot.add_cog(AnalisiForense(bot))
    await bot.add_cog(IntelligenzaMinacce(bot))
    await bot.add_cog(OSINTAvanzato(bot))
    await bot.add_cog(Monitoraggio(bot))
    await bot.add_cog(ComandiBase(bot))
    await bot.add_cog(Moderazione(bot))
    await bot.add_cog(Utilita(bot))

asyncio.run(setup(bot))
bot.run(TOKEN)
