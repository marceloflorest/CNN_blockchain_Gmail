"""
Analiza un Excel completo de correos usando el modelo SiCNN ya entrenado.
La probabilidad la produce SiCNN; la clasificación final aplica además la
lista centralizada de dominios/correos confiables.
"""
import argparse
import numpy as np
import pandas as pd
import tensorflow as tf
from text_to_image import texto_a_imagen
from indicadores import calcular_indicadores
from clasificador import clasificar_correo

ALGORITMO = "SiCNN"


def analizar(df, modelo, col_texto, col_asunto, col_remitente, col_id, col_fecha):
    textos = df[col_texto].fillna("").astype(str)
    asuntos = df[col_asunto].fillna("").astype(str)
    remitentes = df[col_remitente].fillna("").astype(str)
    ids = df[col_id].astype(str) if col_id in df.columns else pd.Series(["N/A"] * len(df))
    fechas = df[col_fecha].astype(str) if col_fecha in df.columns else pd.Series(["N/A"] * len(df))

    print("Convirtiendo correos a imágenes y clasificando (puede tardar unos minutos)...")
    imagenes = np.array([
        texto_a_imagen(a, r, t) for a, r, t in zip(asuntos, remitentes, textos)
    ])

    probas = modelo.predict(imagenes, verbose=0).flatten()
    indicadores = [
        calcular_indicadores(r, a, t) for r, a, t in zip(remitentes, asuntos, textos)
    ]
    reglas = [clasificar_correo(p, r) for p, r in zip(probas, remitentes)]

    reporte = pd.DataFrame({
        "id": ids,
        "fecha_hora": fechas,
        "remitente": remitentes,
        "asunto": asuntos,
        "probabilidad_phishing": probas,
        "clasificacion": [r["clasificacion"] for r in reglas],
        "clasificacion_modelo": [r["clasificacion_modelo"] for r in reglas],
        "dominio": [r["dominio"] for r in reglas],
        "dominio_confiable": [int(r["dominio_confiable"]) for r in reglas],
        # El indicador de correo ahora representa la regla de confianza:
        # 1 = remitente/dominio no confiable, 0 = confiable.
        "ind_correo": [r["indicador_correo"] for r in reglas],
        "ind_url": [i["url"] for i in indicadores],
        "ind_archivo": [i["archivo"] for i in indicadores],
        "ind_imagen": [i["imagen"] for i in indicadores],
        "ind_asunto": [i["asunto"] for i in indicadores],
    })
    return reporte.sort_values("probabilidad_phishing", ascending=False)


def print_report(reporte, mostrar_legitimos=False):
    total = len(reporte)
    phishing = reporte[reporte["clasificacion"] == "PHISHING"]
    legitimos = reporte[reporte["clasificacion"] == "LEGÍTIMO"]

    print(f"\nAlgoritmo: {ALGORITMO}")
    print(f"Total de correos analizados: {total}")
    print(f"Legítimos: {len(legitimos)}")
    print(f"Phishing:  {len(phishing)}\n")
    print("=== Correos marcados como PHISHING ===")
    if len(phishing) == 0:
        print("(ninguno)")
    for _, row in phishing.iterrows():
        print(f"- [{row['probabilidad_phishing']:.1%}] {row['remitente']} | Asunto: {row['asunto']}")
        print(f"  id: {row['id']}")
        print(f"  fecha_hora: {row['fecha_hora']}")
        print(f"  dominio: {row['dominio']} | dominio_confiable: {row['dominio_confiable']}")
        print(f"  correo: {row['ind_correo']}")
        print(f"  url: {row['ind_url']}")
        print(f"  archivo: {row['ind_archivo']}")
        print(f"  imagen: {row['ind_imagen']}")
        print(f"  asunto: {row['ind_asunto']}")
    if mostrar_legitimos:
        print(f"\n=== Correos marcados como LEGÍTIMOS ({len(legitimos)}) ===")
        for _, row in legitimos.iterrows():
            print(f"- [{row['probabilidad_phishing']:.1%}] {row['remitente']} | Asunto: {row['asunto']}")
            print(f"  id: {row['id']}")
            print(f"  fecha_hora: {row['fecha_hora']}")
    else:
        print(f"\n=== Correos LEGÍTIMOS: {len(legitimos)} en total (no listados) ===")
        print("Agrega --mostrar-legitimos si quieres verlos todos en pantalla.")


def save_report_excel(reporte, output_path):
    columnas_orden = [
        "id", "fecha_hora", "remitente", "asunto", "clasificacion", "probabilidad_phishing",
        "ind_correo", "ind_url", "ind_archivo", "ind_imagen", "ind_asunto",
    ]
    reporte_final = reporte[columnas_orden].copy()
    reporte_final["probabilidad_phishing"] = (reporte_final["probabilidad_phishing"] * 100).round(2)

    # Con la nueva regla, los legítimos siempre pertenecen a la lista confiable
    # y por tanto sus indicadores se muestran en 0. En phishing, indicador_correo
    # vale 1 cuando el remitente/dominio no es confiable.
    columnas_indicadores = ["ind_correo", "ind_url", "ind_archivo", "ind_imagen", "ind_asunto"]
    es_legitimo = reporte_final["clasificacion"] == "LEGÍTIMO"
    for col in columnas_indicadores:
        reporte_final.loc[es_legitimo, col] = 0
        reporte_final[col] = reporte_final[col].astype(int)

    reporte_final = reporte_final.rename(columns={
        "probabilidad_phishing": "probabilidad_phishing_%",
        "ind_correo": "indicador_correo",
        "ind_url": "indicador_url",
        "ind_archivo": "indicador_archivo",
        "ind_imagen": "indicador_imagen",
        "ind_asunto": "indicador_asunto",
    })
    reporte_final.to_excel(output_path, index=False, sheet_name="Detalle")
    print(f"\nReporte completo guardado en: {output_path}")


def generar_resumen(reporte):
    total = len(reporte)
    phishing = reporte[reporte["clasificacion"] == "PHISHING"]
    legitimos = reporte[reporte["clasificacion"] == "LEGÍTIMO"]

    pct_legitimos = (len(legitimos) / total * 100) if total else 0
    pct_phishing = (len(phishing) / total * 100) if total else 0
    resumen = {
        "total": total,
        "pct_legitimos": pct_legitimos,
        "pct_phishing": pct_phishing,
        "top_remitente": None,
        "top_remitente_cantidad": 0,
        "top_remitente_pct": 0,
        "indicadores_pct": {},
    }
    if len(phishing) > 0:
        conteo_remitentes = phishing["remitente"].value_counts()
        top_remitente = conteo_remitentes.index[0]
        top_cantidad = int(conteo_remitentes.iloc[0])
        resumen["top_remitente"] = top_remitente
        resumen["top_remitente_cantidad"] = top_cantidad
        resumen["top_remitente_pct"] = (top_cantidad / len(phishing)) * 100
        for col, nombre in [
            ("ind_correo", "correo (dominio sospechoso)"),
            ("ind_url", "url (enlace/llamado a la acción)"),
            ("ind_archivo", "archivo (documento adjunto)"),
            ("ind_imagen", "imagen (imagen adjunta)"),
            ("ind_asunto", "asunto (vacío/anómalo)"),
        ]:
            pct = (phishing[col].sum() / len(phishing)) * 100
            resumen["indicadores_pct"][nombre] = pct
    return resumen


def print_resumen(resumen):
    print(f"\n{'='*50}")
    print("=== RESUMEN GENERAL ===")
    print(f"{'='*50}")
    print(f"Algoritmo: {ALGORITMO}")
    print(f"Total de correos analizados: {resumen['total']}")
    print(f"Porcentaje legítimos: {resumen['pct_legitimos']:.2f}%")
    print(f"Porcentaje phishing: {resumen['pct_phishing']:.2f}%")
    print("\n=== TOP REMITENTE CON MÁS ATAQUES DE PHISHING ===")
    if resumen["top_remitente"]:
        print(f"Remitente: {resumen['top_remitente']}")
        print(f"Cantidad de correos de phishing: {resumen['top_remitente_cantidad']}")
        print(f"Porcentaje sobre el total de phishing: {resumen['top_remitente_pct']:.1f}%")
    else:
        print("(no hay correos de phishing detectados)")
    print("\n=== INDICADORES MÁS FRECUENTES EN LOS CORREOS PHISHING ===")
    if resumen["indicadores_pct"]:
        for nombre, pct in resumen["indicadores_pct"].items():
            print(f"{nombre}: {pct:.1f}% de los phishing")
    else:
        print("(no hay correos de phishing detectados)")


def save_resumen_excel(resumen, output_path):
    """Mantiene el reporte de resumen separado usado por los flujos existentes."""
    filas_generales = [
        {"Métrica": "Algoritmo", "Valor": ALGORITMO},
        {"Métrica": "Total de correos analizados", "Valor": resumen["total"]},
        {"Métrica": "Porcentaje legítimos", "Valor": f"{resumen['pct_legitimos']:.2f}%"},
        {"Métrica": "Porcentaje phishing", "Valor": f"{resumen['pct_phishing']:.2f}%"},
    ]
    filas_top = [
        {"Métrica": "Remitente", "Valor": resumen["top_remitente"] or "(no hay phishing detectado)"},
        {"Métrica": "Cantidad de correos de phishing", "Valor": resumen["top_remitente_cantidad"]},
        {"Métrica": "Porcentaje sobre el total de phishing", "Valor": f"{resumen['top_remitente_pct']:.1f}%"},
    ]
    filas_indicadores = [
        {"Indicador": nombre, "Porcentaje sobre correos phishing": f"{pct:.1f}%"}
        for nombre, pct in resumen["indicadores_pct"].items()
    ] or [{"Indicador": "(no hay correos de phishing detectados)", "Porcentaje sobre correos phishing": ""}]
    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        pd.DataFrame(filas_generales).to_excel(writer, index=False, sheet_name="Resumen general")
        pd.DataFrame(filas_top).to_excel(writer, index=False, sheet_name="Top remitente")
        pd.DataFrame(filas_indicadores).to_excel(writer, index=False, sheet_name="Indicadores")
    print(f"Resumen guardado en: {output_path}")


def generar_resumen_desde_detalle(df):
    """Genera la estructura de Especificaciones a partir del Excel acumulado."""
    trabajo = df.copy()
    if "clasificacion" not in trabajo.columns:
        trabajo["clasificacion"] = ""
    for col in ["indicador_correo", "indicador_url", "indicador_archivo", "indicador_imagen", "indicador_asunto"]:
        if col not in trabajo.columns:
            trabajo[col] = 0
        trabajo[col] = pd.to_numeric(trabajo[col], errors="coerce").fillna(0).astype(int)

    total = len(trabajo)
    phishing = trabajo[trabajo["clasificacion"] == "PHISHING"]
    legitimos = trabajo[trabajo["clasificacion"] == "LEGÍTIMO"]
    pct_legitimos = len(legitimos) / total * 100 if total else 0
    pct_phishing = len(phishing) / total * 100 if total else 0

    if len(phishing):
        conteo = phishing["remitente"].fillna("").value_counts()
        top_remitente = str(conteo.index[0])
        top_cantidad = int(conteo.iloc[0])
        top_pct = top_cantidad / len(phishing) * 100
    else:
        top_remitente, top_cantidad, top_pct = "(no hay phishing detectado)", 0, 0

    indicadores = [
        ("correo (dominio sospechoso)", "indicador_correo"),
        ("url (enlace/llamado a la acción)", "indicador_url"),
        ("archivo (documento adjunto)", "indicador_archivo"),
        ("imagen (imagen adjunta)", "indicador_imagen"),
        ("asunto (vacío/anómalo)", "indicador_asunto"),
    ]
    indicadores_pct = {
        nombre: (phishing[col].sum() / len(phishing) * 100 if len(phishing) else 0)
        for nombre, col in indicadores
    }
    return {
        "total": total,
        "pct_legitimos": pct_legitimos,
        "pct_phishing": pct_phishing,
        "top_remitente": top_remitente,
        "top_remitente_cantidad": top_cantidad,
        "top_remitente_pct": top_pct,
        "indicadores_pct": indicadores_pct,
    }


def save_informe_completo_excel(df, output_path):
    """Guarda el informe acumulado con exactamente dos hojas: Detalle y Especificaciones."""
    columnas = [
        "id", "fecha_hora", "remitente", "asunto", "clasificacion", "probabilidad_phishing_%",
        "indicador_correo", "indicador_url", "indicador_archivo", "indicador_imagen", "indicador_asunto",
    ]
    detalle = df.copy()
    for col in columnas:
        if col not in detalle.columns:
            detalle[col] = "" if col in {"id", "fecha_hora", "remitente", "asunto", "clasificacion"} else 0
    detalle = detalle[columnas].sort_values("probabilidad_phishing_%", ascending=False)

    resumen = generar_resumen_desde_detalle(detalle)
    filas = [
        ("Métrica", "Valor"),
        ("Algoritmo", ALGORITMO),
        ("Total de correos analizados", resumen["total"]),
        ("Porcentaje legítimos", f"{resumen['pct_legitimos']:.2f}%"),
        ("Porcentaje phishing", f"{resumen['pct_phishing']:.2f}%"),
        ("", ""),
        ("Métrica", "Valor"),
        ("Remitente", resumen["top_remitente"]),
        ("Cantidad de correos de phishing", resumen["top_remitente_cantidad"]),
        ("Porcentaje sobre el total de phishing", f"{resumen['top_remitente_pct']:.2f}%"),
        ("", ""),
        ("Indicador", "Porcentaje sobre correos phishing"),
    ]
    for nombre, pct in resumen["indicadores_pct"].items():
        filas.append((nombre, f"{pct:.2f}%"))

    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        detalle.to_excel(writer, index=False, sheet_name="Detalle")
        pd.DataFrame(filas).to_excel(writer, index=False, header=False, sheet_name="Especificaciones")

        ws = writer.book["Especificaciones"]
        ws.column_dimensions["A"].width = 46
        ws.column_dimensions["B"].width = 34
        for row in (1, 7, 12):
            for cell in ws[row]:
                cell.font = cell.font.copy(bold=True)
        ws.freeze_panes = "A2"

    print(f"Informe completo con Especificaciones guardado en: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--modelo", default="sicnn_final.keras")
    parser.add_argument("--sheet", default=0)
    parser.add_argument("--col-texto", default="texto_correo")
    parser.add_argument("--col-asunto", default="asunto")
    parser.add_argument("--col-remitente", default="remitente")
    parser.add_argument("--col-id", default="id")
    parser.add_argument("--col-fecha", default="fecha_hora")
    parser.add_argument("--mostrar-legitimos", action="store_true")
    parser.add_argument("--guardar-excel", default="reporte.xlsx", help="Ruta del Excel de detalle a generar")
    args = parser.parse_args()
    df = pd.read_excel(args.input, sheet_name=args.sheet)
    modelo = tf.keras.models.load_model(args.modelo)

    reporte = analizar(df, modelo, args.col_texto, args.col_asunto, args.col_remitente, args.col_id, args.col_fecha)
    print_report(reporte, mostrar_legitimos=args.mostrar_legitimos)
    save_report_excel(reporte, args.guardar_excel)
    resumen = generar_resumen(reporte)
    print_resumen(resumen)
    base, ext = args.guardar_excel.rsplit(".", 1) if "." in args.guardar_excel else (args.guardar_excel, "xlsx")
    ruta_resumen = f"{base}_resumen.{ext}"
    save_resumen_excel(resumen, ruta_resumen)
