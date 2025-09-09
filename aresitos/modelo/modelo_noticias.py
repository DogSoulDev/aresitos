# =============================================================
# MODELO NOTICIAS - ARESITOS
# =============================================================
# Este modelo gestiona la obtención y almacenamiento temporal de noticias
# de fuentes oficiales de ciberseguridad, usando solo Python nativo.

import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime

class ModeloNoticias:
    DEFAULT_FEEDS = [
        # Feeds verificados y funcionales (septiembre 2025) menos los eliminados por el usuario
        "https://www.ic3.gov/rss.xml",
        "https://www.cyberscoop.com/feed/",
        "https://threatpost.com/feed/",
        "https://www.schneier.com/blog/atom.xml",
        "https://www.krebsonsecurity.com/feed/",
        "https://www.zdnet.com/topic/security/rss.xml",
        "https://www.infosecurity-magazine.com/rss/news/",
        "https://www.helpnetsecurity.com/feed/",
        "https://www.hackread.com/feed/",
        "https://www.securitymagazine.com/rss/15",
        "https://www.securityaffairs.co/feed",
        "http://www.reddit.com/r/netsec/.rss",
        "http://seclists.org/rss/cert.rss",
    # "https://www.cisecurity.org/feed/advisories", # Eliminado por petición del usuario
        "https://www.imperialviolet.org/iv-rss.xml",
        "https://research.kudelskisecurity.com/feed/",
        "http://blog.trailofbits.com/feed/",
        "http://googleprojectzero.blogspot.com/feeds/posts/default",
        "http://postmodernsecurity.com/category/blog-posts/feed/",
        "http://feeds.cyberciti.biz/Nixcraft-LinuxFreebsdSolarisTipsTricks",
    ]

    FEEDS_FILE = "configuración/feeds_noticias.json"

    def __init__(self):
        self.feeds = self.cargar_feeds()

    def cargar_feeds(self):
        import os, json
        if os.path.exists(self.FEEDS_FILE):
            try:
                with open(self.FEEDS_FILE, "r", encoding="utf-8") as f:
                    feeds = json.load(f)
                if isinstance(feeds, list):
                    return feeds
            except Exception:
                pass
        return self.DEFAULT_FEEDS.copy()

    def guardar_feeds(self):
        import json
        with open(self.FEEDS_FILE, "w", encoding="utf-8") as f:
            json.dump(self.feeds, f, ensure_ascii=False, indent=2)

    def agregar_feed(self, url):
        if url not in self.feeds and self.validar_url_feed(url):
            self.feeds.append(url)
            self.guardar_feeds()
            return True
        return False

    def eliminar_feed(self, url):
        if url in self.feeds:
            self.feeds.remove(url)
            self.guardar_feeds()
            return True
        return False

    @staticmethod
    def validar_url_feed(url):
        url = url.lower()
        return url.endswith("rss.xml") or url.endswith(".xml") or url.endswith("/feed")

    def obtener_noticias(self, max_por_fuente=10):
        noticias = []
        for url in self.feeds:
            try:
                with urllib.request.urlopen(url, timeout=10) as response:
                    xml_data = response.read()
                root = ET.fromstring(xml_data)
                for item in root.findall('.//item')[:max_por_fuente]:
                    titulo = item.findtext('title') or "Sin título"
                    enlace = item.findtext('link') or ""
                    fecha = item.findtext('pubDate') or ""
                    fuente = url
                    # Extraer imagen si está presente (media:thumbnail, media:content, image, enclosure)
                    imagen = ""
                    # Buscar media:thumbnail
                    thumb = item.find('{http://search.yahoo.com/mrss/}thumbnail')
                    if thumb is not None and 'url' in thumb.attrib:
                        imagen = thumb.attrib['url']
                    # Buscar media:content
                    if not imagen:
                        media_content = item.find('{http://search.yahoo.com/mrss/}content')
                        if media_content is not None and 'url' in media_content.attrib:
                            imagen = media_content.attrib['url']
                    # Buscar enclosure
                    if not imagen:
                        enclosure = item.find('enclosure')
                        if enclosure is not None and 'url' in enclosure.attrib:
                            imagen = enclosure.attrib['url']
                    # Buscar <image> en el canal (solo si no hay imagen en el item)
                    if not imagen:
                        channel = root.find('channel')
                        if channel is not None:
                            image_tag = channel.find('image')
                            if image_tag is not None:
                                url_tag = image_tag.find('url')
                                if url_tag is not None and url_tag.text:
                                    imagen = url_tag.text.strip()
                    noticias.append({
                        'titulo': titulo.strip(),
                        'enlace': enlace.strip(),
                        'fecha': fecha.strip(),
                        'fuente': fuente,
                        'imagen': imagen
                    })
            except Exception as e:
                noticias.append({
                    'titulo': f"Error al obtener noticias de {url}",
                    'enlace': "",
                    'fecha': str(datetime.now()),
                    'fuente': url,
                    'imagen': ""
                })
        return noticias
