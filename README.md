# Lab_Creacion_Dataset

Laboratorio Dockerizado para crear datasets de imagenes PNG a partir de hashes MD5, SHA1 o SHA256. La UI se muestra como **Laboratorio de creacion de Dataset** con el subtitulo **Transformacion de binarios a png**.

El flujo descarga muestras desde VirusShare, las procesa dentro del contenedor, genera imagenes con `lib_bin2png` y guarda solo los artefactos permitidos en el volumen local. No conserva binarios, ZIPs, muestras originales ni `worker.log`.

## Arranque

Windows:

```cmd
start_lab_docker.cmd
```

Linux/macOS:

```sh
chmod +x start_lab.sh
./start_lab.sh
```

Luego abre:

```text
http://localhost:8000/
```

El contenedor monta la carpeta local `data/` en `/lab/data`, por eso los resultados quedan visibles directamente en el proyecto.

## Configuracion

Para descargar desde VirusShare, define tu API key antes de arrancar:

```cmd
set VIRUSHARE_API_KEY=tu_api_key
start_lab_docker.cmd
```

Tambien puedes pegarla desde la interfaz web en la seccion `Configuracion`. Se guarda localmente en:

```text
data/config.json
```

El laboratorio respeta una solicitud a VirusShare cada 16 segundos:

```cmd
set VIRUSHARE_INTERVAL_SECONDS=16
start_lab_docker.cmd
```

Opcionalmente puedes cambiar el template de descarga:

```cmd
set VIRUSHARE_URL_TEMPLATE=https://virusshare.com/apiv2/download?apikey={api_key}^&hash={hash}
```

Cada ejecucion necesita un lote. Puedes escribir un nombre nuevo o elegir uno existente para agregar hashes a esa misma carpeta.

La UI permite:

- Detener el procesamiento activo.
- Limpiar la lista de trabajos sin borrar carpetas de lotes.
- Terminar el laboratorio.
- Saltar hashes que ya tengan resultados en el lote seleccionado.
- Elegir que imagenes generar: `markov`, `simhash`, `bigram_dct`, `bin2rgb`, `wem`.

## Salidas

Cada hash genera una carpeta con esta estructura:

```text
data/
  jobs.json
  virushare_usage.json
  <nombre_lote>/
    <hash>/
      images/
        markov/*.png
        simhash/*.png
        bigram_dct/*.png
        bin2rgb/*.png
        wem/*.png
      analysis/
        static_analysis.json
      metadata.json
```

El binario y el ZIP se usan solo como temporales dentro del contenedor. Al finalizar, el worker elimina el directorio temporal completo.

## Analisis estatico

Antes de generar las imagenes, el worker crea:

```text
data/<nombre_lote>/<hash>/analysis/static_analysis.json
```

El reporte incluye:

- Hashes `md5`, `sha1` y `sha256`.
- Tamano, entropia, proporcion imprimible, histograma de bytes y bytes mas frecuentes.
- Identificacion con `file` y tipo MIME.
- Strings ASCII limitadas para evitar JSON gigantes.
- IOCs: URLs, dominios, IPv4, correos, rutas Windows, llaves de registro y comandos sospechosos.
- Metadata con `exiftool`, incluyendo fechas como `CreateDate` cuando existen.
- Analisis PE con `pefile`: timestamp, cabecera, secciones, imports y exports.
- Analisis ELF con `readelf`.
- Heuristicas PDF: objetos, streams y tokens como `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, `/XFA`, `/Encrypt`, `/URI` y `/SubmitForm`.
- Coincidencias YARA con reglas locales.
- Cabecera de objeto con `objdump`.

La UI muestra un resumen del analisis en el detalle de cada trabajo, incluyendo fecha legible, IOCs, PDF, YARA, PE, ELF y enlace al JSON completo.

## Reglas YARA

Las reglas locales viven en:

```text
worker/yara_rules/lab_static.yar
```

El conjunto base cubre:

- PDF con contenido activo, embebido, cifrado, formularios o enlaces externos.
- Scripts con PowerShell codificado, descarga y ejecucion.
- Comandos Windows tipo LOLBins.
- PE con APIs de red, persistencia, modificacion del sistema, antidebug, VM y credenciales/navegadores.
- Office OLE/OOXML con macros o relaciones externas.
- ZIP con indicadores JAR/APK.
- ELF con ejecucion, tracing o red.
- Blobs base64 de alto valor.

Puedes agregar mas reglas creando archivos `.yar` o `.yara` dentro de `worker/yara_rules/`. El worker carga todos esos archivos al analizar cada muestra.

Para validar reglas dentro de la imagen Docker:

```cmd
docker run --rm --entrypoint yara lab-creacion-dataset:local /lab/worker/yara_rules/lab_static.yar /bin/ls
```

## Politica de artefactos

La carpeta `data/` es local y no debe subirse al repositorio. Ahi quedan los lotes, imagenes generadas, estado runtime, metadata y reportes de analisis.

No se debe versionar:

```text
.env
data/*
```

La configuracion actual de `.gitignore` mantiene solo `data/.gitkeep` para conservar la carpeta vacia en Git. Todo lote generado queda fuera del repo.

## Limpieza

Para limpiar solo la cola visible en la UI, usa el boton **Limpiar lista**. Eso vacia `data/jobs.json` y no borra lotes ni imagenes.

Para eliminar lotes de prueba, borra manualmente la carpeta completa del lote dentro de `data/`, por ejemplo:

```cmd
rmdir /s /q data\lote_de_prueba
```

No borres lotes reales si ya forman parte del dataset. Los nombres como `proof`, `proof1`, `prueba` o `pueba1` suelen ser pruebas locales; revisalos antes de quitarlos.

## Portabilidad

Para preparar una computadora nueva:

```cmd
git clone <url-del-repo>
cd <repo>
copy .env.example .env
notepad .env
start_lab_docker.cmd
```

En Linux/macOS:

```sh
git clone <url-del-repo>
cd <repo>
cp .env.example .env
${EDITOR:-nano} .env
./start_lab.sh
```

Antes del primer commit puedes revisar que la API key y los JSON locales no vayan incluidos:

```cmd
git status --short
git status --ignored --short
```
