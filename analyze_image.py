"""Analiza capturas de pantalla reales de correos con OCR + SiCNN."""
import argparse
import os
import csv
import numpy as np
import tensorflow as tf
import pandas as pd

from ocr_utils import extract_text_from_image
from text_to_image import texto_a_imagen
from indicadores import calcular_indicadores
from clasificador import clasificar_correo

ALGORITMO = "SiCNN"
EXTENSIONES_VALIDAS = (".png", ".jpg", ".jpeg", ".bmp")


def cargar_metadata(ruta_csv):
    metadata = {}
    if not ruta_csv:
        return metadata
    with open(ruta_csv, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            metadata[row["archivo"]] = {
                "remitente": row.get("remitente", ""),
                "asunto": row.get("asunto", ""),
            }
    return metadata


def analizar_carpeta(carpeta, modelo, metadata):
    archivos = sorted([f for f in os.listdir(carpeta) if f.lower().endswith(EXTENSIONES_VALIDAS)])
    if not archivos:
        print(f"No se encontraron imágenes en {carpeta}")
        return None

    filas = []
    for archivo in archivos:
        ruta = os.path.join(carpeta, archivo)
        print(f"Procesando {archivo} (OCR)...")
        texto_extraido = extract_text_from_image(ruta)
        meta = metadata.get(archivo, {"remitente": archivo, "asunto": "(sin asunto)"})
        remitente = meta["remitente"]
        asunto = meta["asunto"]

        if not texto_extraido:
            proba = 0.0
        else:
            imagen = texto_a_imagen(asunto, remitente, texto_extraido)
            imagen = np.expand_dims(imagen, axis=0)
            proba = float(modelo.predict(imagen, verbose=0)[0][0])

        regla = clasificar_correo(proba, remitente)
        indicadores = calcular_indicadores(remitente, asunto, texto_extraido)
        filas.append({
            "archivo": archivo,
            "remitente": remitente,
            "asunto": asunto,
            "texto_extraido": texto_extraido,
            "probabilidad_phishing": proba,
            "clasificacion": regla["clasificacion"],
            "clasificacion_modelo": regla["clasificacion_modelo"],
            "dominio": regla["dominio"],
            "dominio_confiable": int(regla["dominio_confiable"]),
            "ind_correo": regla["indicador_correo"],
            "ind_url": indicadores["url"],
            "ind_archivo": indicadores["archivo"],
            "ind_imagen": indicadores["imagen"],
            "ind_asunto": indicadores["asunto"],
        })
    reporte = pd.DataFrame(filas)
    return reporte.sort_values("probabilidad_phishing", ascending=False)


def generar_resumen_imagenes(reporte):
    total = len(reporte)
    phishing = reporte[reporte["clasificacion"] == "PHISHING"]
    legitimos = reporte[reporte["clasificacion"] == "LEGÍTIMO"]
    resumen = {
        "total": total,
        "pct_legitimos": (len(legitimos) / total * 100) if total else 0,
        "pct_phishing": (len(phishing) / total * 100) if total else 0,
        "top_remitente": None,
        "top_remitente_cantidad": 0,
        "top_remitente_pct": 0,
        "indicadores_pct": {},
    }
    if len(phishing) > 0:
        conteo = phishing["remitente"].value_counts()
        resumen["top_remitente"] = conteo.index[0]
        resumen["top_remitente_cantidad"] = int(conteo.iloc[0])
        resumen["top_remitente_pct"] = (int(conteo.iloc[0]) / len(phishing)) * 100
        for col, nombre in [
            ("ind_correo", "correo (dominio sospechoso)"),
            ("ind_url", "url (enlace/llamado a la acción)"),
            ("ind_archivo", "archivo (documento adjunto)"),
            ("ind_imagen", "imagen (imagen adjunta)"),
            ("ind_asunto", "asunto (vacío/anómalo)"),
        ]:
            resumen["indicadores_pct"][nombre] = (phishing[col].sum() / len(phishing)) * 100
    return resumen


def imprimir_y_guardar(reporte, resumen, ruta_salida):
    lineas = []
    lineas.append(f"=== INFORME DE IMÁGENES ANALIZADAS ({ALGORITMO}) ===")
    lineas.append(f"Total de imágenes analizadas: {resumen['total']}")
    lineas.append(f"Porcentaje legítimos: {resumen['pct_legitimos']:.2f}%")
    lineas.append(f"Porcentaje phishing: {resumen['pct_phishing']:.2f}%\n")
    lineas.append("=== DETALLE POR IMAGEN ===")
    phishing = reporte[reporte["clasificacion"] == "PHISHING"]
    legitimos = reporte[reporte["clasificacion"] == "LEGÍTIMO"]
    lineas.append("--- PHISHING ---")
    if len(phishing) == 0:
        lineas.append("(ninguno)")
    for _, row in phishing.iterrows():
        lineas.append(f"- [{row['probabilidad_phishing']:.1%}] {row['archivo']} | Remitente: {row['remitente']} | Asunto: {row['asunto']}")
        lineas.append(f"  dominio: {row['dominio']} | dominio_confiable: {row['dominio_confiable']}")
        lineas.append(f"  correo: {row['ind_correo']}")
        lineas.append(f"  url: {row['ind_url']}")
        lineas.append(f"  archivo: {row['ind_archivo']}")
        lineas.append(f"  imagen: {row['ind_imagen']}")
        lineas.append(f"  asunto: {row['ind_asunto']}")
    lineas.append("\n--- LEGÍTIMOS ---")
    if len(legitimos) == 0:
        lineas.append("(ninguno)")
    for _, row in legitimos.iterrows():
        lineas.append(f"- [{row['probabilidad_phishing']:.1%}] {row['archivo']} | Remitente: {row['remitente']} | Asunto: {row['asunto']}")
    lineas.append("\n=== RESUMEN ===")
    lineas.append("Top remitente con más ataques de phishing:")
    if resumen["top_remitente"]:
        lineas.append(f"Remitente: {resumen['top_remitente']}")
        lineas.append(f"Cantidad de correos de phishing: {resumen['top_remitente_cantidad']}")
        lineas.append(f"Porcentaje sobre el total de phishing: {resumen['top_remitente_pct']:.1f}%")
    else:
        lineas.append("(no hay imágenes de phishing detectadas)")
    lineas.append("\nIndicadores más frecuentes en las imágenes de phishing:")
    if resumen["indicadores_pct"]:
        for nombre, pct in resumen["indicadores_pct"].items():
            lineas.append(f"{nombre}: {pct:.1f}% de los phishing")
    else:
        lineas.append("(no hay imágenes de phishing detectadas)")

    texto_final = "\n".join(lineas)
    print("\n" + texto_final)
    with open(ruta_salida, "w", encoding="utf-8") as f:
        f.write(texto_final)
    print(f"\nInforme de imágenes guardado en: {ruta_salida}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--images", required=True, help="Carpeta con las imágenes a analizar")
    parser.add_argument("--modelo", default="sicnn_final.keras")
    parser.add_argument("--metadata", default=None, help="CSV opcional: archivo,remitente,asunto")
    parser.add_argument("--guardar-txt", default="reporte_imagenes.txt")
    args = parser.parse_args()
    modelo = tf.keras.models.load_model(args.modelo)
    metadata = cargar_metadata(args.metadata)

    reporte = analizar_carpeta(args.images, modelo, metadata)
    if reporte is None:
        exit()

    resumen = generar_resumen_imagenes(reporte)
    imprimir_y_guardar(reporte, resumen, args.guardar_txt)
