# =============================================================
# CONTROLADOR NOTICIAS - ARESITOS
# =============================================================
# Controla la lógica de actualización y filtrado de noticias.

from aresitos.modelo.modelo_noticias import ModeloNoticias

class ControladorNoticias:
    def agregar_feed(self, url):
        return self.modelo.agregar_feed(url)

    def eliminar_feed(self, url):
        return self.modelo.eliminar_feed(url)

    def obtener_feeds(self):
        return self.modelo.feeds
    def __init__(self):
        self.modelo = ModeloNoticias()
        self.noticias = []

    def actualizar_noticias(self):
        self.noticias = self.modelo.obtener_noticias()
        return self.noticias

    def filtrar_noticias(self, texto):
        texto = texto.lower()
        return [n for n in self.noticias if texto in n['titulo'].lower() or texto in n['fuente'].lower()]
