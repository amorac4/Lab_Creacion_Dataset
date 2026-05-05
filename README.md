# Lab_Creacion_Dataset

Laboratorio local para procesar hashes dentro de Docker. El laboratorio descarga y descomprime muestras solo como archivos temporales dentro del contenedor; en el volumen local conserva unicamente imagenes y metadata.

La interfaz se muestra como **Laboratorio de creacion de Dataset** con el subtitulo **Transformacion de binarios a png**.

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

El laboratorio limita las consultas a VirusShare a una solicitud cada 16 segundos. Puedes cambiarlo antes de arrancar con:

```cmd
set VIRUSHARE_INTERVAL_SECONDS=16
start_lab_docker.cmd
```

La interfaz incluye controles para detener el procesamiento activo, limpiar la lista de trabajos y terminar el laboratorio. Limpiar la lista no borra carpetas de lotes; solo vacia `data/jobs.json`.

En configuracion tambien puedes activar:

- Saltar un hash si ya tiene resultados guardados dentro del lote seleccionado.
- Elegir que tipos de imagen generar por lote: `markov`, `simhash`, `bigram_dct`, `bin2rgb`, `wem`.

Cada ejecucion necesita un lote. Puedes escribir un nombre nuevo o elegir uno existente desde la lista para agregar mas hashes a esa misma carpeta.

Opcionalmente puedes cambiar el template de descarga:

```cmd
set VIRUSHARE_URL_TEMPLATE=https://virusshare.com/apiv2/download?apikey={api_key}^&hash={hash}
```

## Salidas

```text
data/
  jobs.json
  <nombre_lote>/
    <hash>/
      images/
      metadata.json
```

El binario no se ejecuta ni se conserva. Solo se descarga, descomprime, verifica y convierte a imagen dentro del contenedor; los temporales se eliminan al finalizar.

## Portabilidad

El repositorio esta preparado para subir codigo e imagenes generadas, pero no secretos.

Archivos que no deben subirse:

```text
.env
data/config.json
data/jobs.json
data/virushare_usage.json
data/**/metadata.json
```

Las imagenes generadas si pueden subirse:

```text
data/<nombre_lote>/<hash>/images/**/*.png
```

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

Antes del primer commit puedes revisar que la API key no vaya incluida:

```cmd
git status --short
git status --ignored --short
```

Si usas la UI para guardar la API key, queda en `data/config.json`, que esta ignorado por Git.
