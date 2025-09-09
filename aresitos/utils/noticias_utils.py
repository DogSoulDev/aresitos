# =============================================================
# UTILS NOTICIAS - ARESITOS
# =============================================================
# Funciones auxiliares para el módulo de noticias.

# Si necesitas procesar fechas, limpiar texto, etc., puedes añadir aquí funciones auxiliares.

def limpiar_titulo(titulo):
    return titulo.replace('\n', ' ').strip()

def formatear_fecha(fecha):
    # Intentar formatear la fecha RSS a formato legible
    import email.utils
    try:
        dt = email.utils.parsedate_to_datetime(fecha)
        return dt.strftime('%d/%m/%Y %H:%M')
    except Exception:
        return fecha
