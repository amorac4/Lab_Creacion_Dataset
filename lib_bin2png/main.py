import json, time, os
from funciones import GeneradorDeImagenes
from concurrent.futures import ProcessPoolExecutor, as_completed
from funciones import markov, simhash, bigram_dct, bin2rgb, wem


def main():

    try:
        # Detectar el número de núcleos del CPU
        max_workers = os.cpu_count()
        print(f"[*] Número de procesos paralelos: {max_workers}")

        # Medir tiempo total de ejecución
        inicio_total = time.time()

        with open('config_imagenes.json', 'r') as f:
            config = json.load(f)

        algorithms = config['algorithms']
        input_dir = config['input_dir']

        tareas = []
        tiempos = {}

        # === EJECUCIÓN EN PARALELO CON PROCESOS ===
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            for algorithm in algorithms:
                output_dir = os.path.join('Images', algorithm)
                os.makedirs(output_dir, exist_ok=True)

                # Añadir tareas al pool de procesos
                for file in os.listdir(input_dir):
                    if file.lower().endswith('.exe'):
                        print(f"[*] Encolando tarea: {file} para {algorithm}")
                        future = executor.submit(
                            GeneradorDeImagenes.procesar_archivo,
                            algorithm, file, input_dir, output_dir
                        )
                        tareas.append((future, file, algorithm))

            # Recolectar resultados en orden de finalización
            for future in as_completed([t[0] for t in tareas]):
                try:
                    idx = [t[0] for t in tareas].index(future)
                    file, algorithm = tareas[idx][1], tareas[idx][2]
                    future.result()
                    print(f"[✓] {file} procesado con {algorithm}")
                except Exception as e:
                    print(f'[X] Error en ejecución paralela: {e}')

        # Tiempo total
        fin_total = time.time()
        duracion_total = fin_total - inicio_total
        print(f"\n===== Procesamiento Completo =====")
        print(f"Tiempo total de procesamiento: {duracion_total:.2f} segundos")

        # Bitacora log
        log_dir = os.path.join('Images', "registro_operaciones.log")
        with open(log_dir, 'a') as log_file:
            log_file.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Tiempo total: {duracion_total:.2f} segundos\n")

    except Exception as e:
        print(f'[X] Error en el procesamiento principal: {e}')


if __name__ == "__main__":
    main()
