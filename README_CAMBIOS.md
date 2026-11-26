# Cambios propuestos para SiCNN + Gmail

Estos archivos implementan las tres consultas del documento `propuestas para IA.docx`.

## Archivos nuevos/reemplazados

- `clasificador.py`: regla centralizada de dominios/correos confiables.
- `analyze_excel.py`: clasificación Excel con la misma regla y generación de datos para `Especificaciones`.
- `analyze_image.py`: aplica exactamente la misma regla a imágenes/OCR.
- `web_app.patch`: cambios mínimos para `web_app.py`.

## Regla final

1. SiCNN siempre calcula `probabilidad_phishing`.
2. Se conserva la clasificación pura del modelo en `clasificacion_modelo`.
3. La lista confiable tiene precedencia para la clasificación final:
   - confiable -> `LEGÍTIMO` y `indicador_correo = 0`;
   - no confiable -> `PHISHING` y `indicador_correo = 1`.
4. Los indicadores URL, archivo, imagen y asunto siguen calculándose por sus reglas actuales.
5. Para correos legítimos se mantienen los demás indicadores en 0 en el Excel, como hacía el software anterior.
6. `/descargar-informe` genera ahora `Detalle` + `Especificaciones` en el mismo Excel acumulado.

## Importante sobre el entrenamiento

No se modifica `train.py`. El modelo existente continúa siendo el modelo entrenado con la regla original basada en `essalud.gob.pe`. La lista de 30 dominios se usa como regla de decisión de la aplicación en inferencia, por lo que no es necesario reentrenar para aplicar este cambio.

Esto permite que SiCNN siga analizando el contenido y produzca su probabilidad, mientras la política de dominios determina la clasificación final del escenario actual.

## Aplicación

1. Copiar `clasificador.py` al directorio raíz.
2. Reemplazar `analyze_excel.py` y `analyze_image.py` por los archivos de esta carpeta.
3. Aplicar `web_app.patch` a `web_app.py`.
4. No es necesario modificar `Code.gs`: el complemento ya utiliza la clasificación devuelta por `/api/analizar`, por lo que las etiquetas Gmail heredarán la nueva regla.
5. Reiniciar Flask/ngrok antes de probar Gmail.
