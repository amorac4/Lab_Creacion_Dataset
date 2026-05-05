import os, cv2, json, hashlib, capstone, time
import numpy as np
from PIL import Image
from math import ceil, log2
from scipy.fftpack import dct
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed


class GeneradorDeImagenes:   

    def procesar_archivo(algorithm, file, input_dir, output_dir):
        
        method = mapping.get(algorithm, None)
        if not method:
            print(f'[!] Técnica no soportada: {algorithm}')
            return

        entrada = os.path.join(input_dir, file)
        salida = os.path.join(output_dir, f"{os.path.splitext(file)[0]}.png")
        
        print(f"[*] Ejecutando: {algorithm} para {file}")
        start_time = time.time()
        
        try:
            method(entrada, salida)
            end_time = time.time()
            duracion = end_time - start_time
            print(f"[✓] {file} procesado con {algorithm} en {duracion:.2f} segundos")
        except Exception as e:
            print(f"[X] Error procesando {file} con {algorithm}: {e}")


#----------------------
# Algorithm 1: DCT
#----------------------
def bigram_dct (entrada: str, salida: str):

        try:
            with open(entrada,'rb') as f:
                contenido = f.read()
            
            bigramas = []

            for i in range(len(contenido) - 1):
                bigrama = contenido [i] << 8 | contenido[i+1]
                bigramas.append(bigrama)
            bigramas = np.array(bigramas)

            frecuencia = np.bincount(bigramas, minlength=256 * 256)
            frecuencia = frecuencia.reshape((256, 256))
            frecuencia[0, 0] = 0

            frecuencia = frecuencia / np.max(frecuencia)

            frecuencia_dct = dct(dct(frecuencia.T, norm='ortho').T, norm='ortho')
            frecuencia_dct -= np.min(frecuencia_dct)
            frecuencia_dct /= np.max(frecuencia_dct)

            imagen = (frecuencia_dct * 255).astype(np.uint8)
            Image.fromarray(imagen).save(salida)
            print(f"Imagen guardada en: {salida}")
        except Exception as e:
            print(f"Error en bigram_dct: {e}")


#----------------------
# Algorithm 2: Bin2grb
#----------------------
def bin2rgb (entrada: str, salida: str):

        try:
            with open(entrada, 'rb') as f:
                contenido = f.read()

            datos = np.frombuffer(contenido, dtype=np.uint8)

            size_kb = len(contenido) / 1024
            if size_kb < 10:
                ancho = 32
            elif size_kb < 30:
                ancho = 64
            elif size_kb < 60:
                ancho = 128
            elif size_kb < 100:
                ancho = 256
            elif size_kb < 200:
                ancho = 384
            elif size_kb < 500:
                ancho = 512
            elif size_kb < 1000:
                ancho = 768
            else:
                ancho = 1024

            alto = max(1, int(np.ceil(len(datos) / (ancho * 3))))
            tbytes = ancho * alto * 3

            if len(datos) < tbytes:
                datos = np.pad(datos, (0, tbytes - len(datos)), mode='constant', constant_values=0)

            imagen_array = datos.reshape((alto, ancho, 3))
            imagen = Image.fromarray(imagen_array.astype('uint8'), 'RGB')
            imagen.save(salida)
            print(f"Imagen guardada en: {salida}")
        except Exception as e:
            print(f"Error en bin2rgb: {e}")

 
#----------------------
# Algorithm 3: SimHash
#----------------------
def simhash(entrada: str, salida: str, force: bool = False):

        def extract_opcodes(file_path, force=False):
            with open(file_path, "rb") as f:
                header = f.read(2)
                if header != b'MZ':
                    print(f"[X] {file_path} no tiene firma PE válida. Skipping...")
                    return []

                # Leer el offset del PE Header
                f.seek(0x3C)
                pe_offset = int.from_bytes(f.read(4), byteorder='little')

                # Leer el Entry Point
                f.seek(pe_offset + 0x28)
                entry_point = int.from_bytes(f.read(4), byteorder='little')
                
                # Leer el Tamaño de Imagen para validar si es 64 bits
                f.seek(pe_offset + 0x18)
                machine = int.from_bytes(f.read(2), byteorder='little')

                print(f"[*] Entry Point detectado en: 0x{entry_point:X}")
                print(f"[*] Arquitectura detectada: {'x64' if machine == 0x8664 else 'x86'}")

                # Leer el binario completo
                f.seek(0)
                binary = f.read()

            opcodes = []

            # --- Probar según arquitectura detectada ---
            if machine == 0x8664:
                print(f"[*] Intentando extraer en modo 64 bits desde 0x{entry_point:X}...")
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                print(f"[*] Intentando extraer en modo 32 bits desde 0x{entry_point:X}...")
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

            try:
                for instr in md.disasm(binary[entry_point:], entry_point):
                    if instr.mnemonic:
                        opcodes.append(instr.mnemonic)
            except Exception as e:
                print(f"[!] Error en desensamblado: {e}")

            # --- Probar en ARM si no hay resultados ---
            if not opcodes:
                try:
                    print("[*] Intentando extraer en modo ARM...")
                    md_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
                    for instr in md_arm.disasm(binary[entry_point:], entry_point):
                        if instr.mnemonic:
                            opcodes.append(instr.mnemonic)
                except Exception as e:
                    print(f"[!] Error en ARM: {e}")

            if not opcodes:
                print(f"[X] No se extrajeron opcodes de {file_path}. Skipping...")

            return opcodes

        def multihash_opcode(opcode):
            sha512 = hashlib.sha512(opcode.encode('utf-8')).hexdigest()
            sha256 = hashlib.sha256(opcode.encode('utf-8')).hexdigest()
            combined = sha512 + sha256
            bin_hash = bin(int(combined, 16))[2:].zfill(768)
            return bin_hash

        def compute_multihash_simhash(opcodes):
            v = [0] * 768
            for opcode in opcodes:
                bin_hash = multihash_opcode(opcode)
                for i in range(768):
                    v[i] += 1 if bin_hash[i] == '1' else -1
            simhash = ''.join(['1' if x > 0 else '0' for x in v])
            return simhash

        def simhash_to_image(simhash, output_path):
            bits = len(simhash)
            width = int(np.sqrt(bits))
            height = width
            if width * height < bits:
                height += 1

            img = np.zeros((height, width), dtype=np.uint8)

            for idx, bit in enumerate(simhash):
                i = idx // width
                j = idx % width
                if i < img.shape[0] and j < img.shape[1]:
                    img[i, j] = 255 if bit == '1' else 0

            image = Image.fromarray(img, mode='L')
            image = image.resize((32, 32), Image.BILINEAR)
            image.save(output_path)

        # --- Proceso completo ---
        try:
            print(f"[*] Procesando {entrada}...")
            opcodes = extract_opcodes(entrada, force)

            if not opcodes:
                print(f"[X] No se pudieron extraer opcodes de {entrada}. Skipping...")
                return

            print(f"[*] {len(opcodes)} opcodes extraídos.")
            print(f"    Ejemplo de opcodes: {opcodes[:10]}")
            simhash = compute_multihash_simhash(opcodes)
            print(f"    SimHash (primeros 32 bits): {simhash[:32]}")
            simhash_to_image(simhash, salida)
            print(f"[✓] Imagen guardada en: {salida}")
        except Exception as e:
            print(f'[X] Error en simhash: {e}')


#----------------------
# Algorithm 4: Byte-markov
#----------------------
def markov(entrada: str, salida: str):

        try:    
            with open(entrada, 'rb') as f:
                datos = f.read()

            matriz_frecuencia = np.zeros((256, 256), dtype=np.uint32)

            for i in range(len(datos) - 1):
                byteA = datos[i]
                byteS = datos[i + 1]
                matriz_frecuencia[byteA, byteS] += 1
            
            sum_filas = matriz_frecuencia.sum(axis=1, keepdims=True)
            sum_filas[sum_filas == 0] = 1
            matriz_probabilidad = matriz_frecuencia / sum_filas

            img = (matriz_probabilidad * 255).astype(np.uint8)

            imagen = Image.fromarray(img, mode='L')
            imagen.save(salida)
            print(f"Imagen guardada en: {salida}")
        except Exception as e:
            print(f"Error en markov: {e}")


#----------------------
# Algorithm 5: WEM
#----------------------
def wem(entrada: str, salida: str, window_size: int = 1024, step_size: int = 256, L: int = 2, delta: float = 0.2, shape=(16, 32)):

        try:
            with open(entrada, 'rb') as f:
                byte_seq = list(f.read())

            T = (len(byte_seq) - window_size) // step_size + 1
            if T <= 0:
                raise ValueError("Archivo muy pequeño para construir WEM")

            H = np.zeros((T, 256))  
            B = np.zeros((L, 256))  

            for k in range(T):
                window = byte_seq[k * step_size : k * step_size + window_size]
                counts = Counter(window)
                total = len(window)
                
                for j in range(256):
                    p = counts.get(j, 0) / total
                    if p > 0:
                        H[k][j] = -p * log2(p)

            C = np.cumsum(H, axis=0)
            for k in range(T):
                for j in range(256):
                    l = ceil(C[k][j] / delta)
                    l = max(1, min(L, l)) - 1
                    B[l][j] += H[k][j]

            flat = B.flatten()
            img_array = flat.reshape(shape)
            img_array = (img_array / np.max(img_array) * 255).astype(np.uint8)

            Image.fromarray(img_array, mode='L').save(salida)
            print(f'[✓] Imagen WEM guardada en: {salida}')

        except Exception as e:
            print(f'[X] Error en WEM: {e}')

mapping = {
            'bigram_dct': bigram_dct,
            'bin2rgb':    bin2rgb,
            'simhash':    simhash,
            'markov':     markov,
            'wem':        wem
}
