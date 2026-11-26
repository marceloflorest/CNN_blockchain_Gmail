"""
Reglas centralizadas de clasificación para SiCNN.

SiCNN sigue calculando la probabilidad de phishing a partir del contenido del
correo. La regla de dominio se aplica después y determina la clasificación
final para el escenario definido para el proyecto:

- remitente/dominio confiable -> LEGÍTIMO
- remitente/dominio no confiable -> PHISHING

La probabilidad producida por SiCNN se conserva para el reporte y el análisis.
"""
import re
from typing import Optional

# Dominios autorizados para el escenario actual del software.
DOMINIOS_CONFIABLES = [
    "essalud.gob.pe",
    "bcp.com.pe",
    "email.bcp.com.pe",
    "notificacionesbcp.com.pe",
    "interbank.pe",
    "banbif.com.pe",
    "bancom.com.pe",
    "scotiabank.com.pe",
    "mapfre.com.pe",
    "pih.org",
    "astrazeneca.com",
    "ilo.org",
    "conafovicer.com",
    "servir.gob.pe",
    "sis.gob.pe",
    "inei.gob.pe",
    "uns.edu.pe",
    "coopsanjorge.com.pe",
    "sunat.gob.pe",
    "onp.gob.pe",
    "reniec.gob.pe",
    "ins.gob.pe",
    "minsa.gob.pe",
    "bnp.gob.pe",
    "paho.org",
    "comexperu.org.pe",
    "indecopi.gob.pe",
    "mtc.gob.pe",
    "gob.pe",
]

# Direcciones concretas que también aparecen en la lista del documento.
CORREOS_CONFIABLES = [
    "notificaciones@notificacionesbcp.com.pe",
]

UMBRAL_SICNN = 0.50


def extraer_email(remitente: str) -> str:
    """Extrae una dirección de correo incluso si Gmail devuelve 'Nombre <correo>'."""
    texto = str(remitente or "").strip().lower()
    coincidencia = re.search(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}", texto)
    return coincidencia.group(0) if coincidencia else ""


def extraer_dominio(remitente: str) -> str:
    """Obtiene únicamente el dominio de la dirección del remitente."""
    email = extraer_email(remitente)
    if not email:
        return ""
    return email.rsplit("@", 1)[1].strip(". ")


def _normalizar_lista(items):
    return {str(item).strip().lower().lstrip("@").rstrip(".") for item in items if str(item).strip()}


_DOMINIOS = _normalizar_lista(DOMINIOS_CONFIABLES)
_CORREOS = _normalizar_lista(CORREOS_CONFIABLES)


def dominio_es_confiable(remitente: str) -> bool:
    """Comprueba si el correo o su dominio pertenece a la lista confiable."""
    email = extraer_email(remitente)
    dominio = extraer_dominio(remitente)

    if email and email in _CORREOS:
        return True

    if not dominio:
        return False

    # Coincidencia exacta o subdominio de una entrada confiable.
    return any(dominio == d or dominio.endswith("." + d) for d in _DOMINIOS)


def clasificar_correo(probabilidad_phishing: float, remitente: str):
    """
    Devuelve clasificación final, clasificación pura del modelo e indicador
    de correo. La lista confiable tiene precedencia sobre SiCNN.
    """
    proba = float(probabilidad_phishing)
    clasificacion_modelo = "PHISHING" if proba >= UMBRAL_SICNN else "LEGÍTIMO"
    confiable = dominio_es_confiable(remitente)

    if confiable:
        clasificacion_final = "LEGÍTIMO"
        indicador_correo = 0
    else:
        clasificacion_final = "PHISHING"
        indicador_correo = 1

    return {
        "clasificacion": clasificacion_final,
        "clasificacion_modelo": clasificacion_modelo,
        "indicador_correo": indicador_correo,
        "dominio_confiable": confiable,
        "dominio": extraer_dominio(remitente),
        "correo_extraido": extraer_email(remitente),
    }
