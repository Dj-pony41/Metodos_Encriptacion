import time
import psutil
import tracemalloc
import tkinter as tk
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import base64
import hashlib
import os
import threading

# Crear la carpeta "revisar" si no existe
if not os.path.exists("revisar"):
    os.makedirs("revisar")

# Función para medir el rendimiento
def measure_performance(encrypt_func, decrypt_func, text, iterations, method_name):
    print(f"[LOG] Iniciando prueba para: {method_name}")
    tracemalloc.start()
    process = psutil.Process()
    start_mem = process.memory_info().rss
    start_cpu = time.process_time()
    start_time = time.time()
    print(f"[LOG] Iniciando prueba para: {method_name}")

    try:
        encrypted_data = encrypt_func(text)
        print(f"[LOG] {method_name} encriptado correctamente.")
        for _ in range(iterations - 1):
            encrypt_func(text)

        decrypted_data = decrypt_func(encrypted_data) if encrypted_data is not None else None
        print(f"[LOG] {method_name} desencriptado correctamente.")
        for _ in range(iterations - 1):
            if encrypted_data is not None:
                decrypt_func(encrypted_data)

        end_time = time.time()
        end_cpu = time.process_time()
        peak_mem = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()

        # Guardar en archivo
        encrypted_file_path = f"revisar/{method_name}_encriptado.txt"
        decrypted_file_path = f"revisar/{method_name}_desencriptado.txt"

        if method_name == "Year Encryption":
            if isinstance(encrypted_data, dict) and "Error" in encrypted_data:
                raise Exception(encrypted_data["Error"])

            with open(encrypted_file_path, "wb") as enc_file:
                enc_file.write(str(encrypted_data).encode())  # ✅ Guarda la lista como string

        else:
            with open(encrypted_file_path, "wb") as enc_file:
                enc_file.write(str(encrypted_data).encode())

        with open(decrypted_file_path, "w", encoding="utf-8") as dec_file:
            dec_file.write(decrypted_data if decrypted_data else "Error en desencriptado")

        return {
            'Time (s)': round(end_time - start_time, 6),
            'CPU Time (s)': round(end_cpu - start_cpu, 6),
            'Memory (bytes)': peak_mem
        }

    except Exception as e:
        print(f"[ERROR] Fallo en {method_name}: {str(e)}")
        return {"Error": str(e)}



# Métodos de cifrado
def aes_encrypt(text):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return key, cipher.nonce, ciphertext, tag

def aes_decrypt(data):
    key, nonce, ciphertext, tag = data
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def fernet_encrypt(text):
    key = Fernet.generate_key()
    cipher = Fernet(key)
    return key, cipher.encrypt(text.encode())

def fernet_decrypt(data):
    key, encrypted_text = data
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_text).decode()

def rsa_encrypt(text):
    try:
        aes_key = get_random_bytes(16)  # Generamos una clave AES de 16 bytes
        cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(text.encode())

        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return (encrypted_key, cipher.nonce, ciphertext, tag)  # Retornamos la clave cifrada y el mensaje cifrado
    except Exception as e:
        return {"Error": str(e)}

def rsa_decrypt(data):
    try:
        encrypted_key, nonce, ciphertext, tag = data

        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except Exception as e:
        return {"Error": str(e)}


def xor_encrypt(text):
    key = 42
    return bytes([b ^ key for b in text.encode()])

def xor_decrypt(encrypted_data):
    key = 42
    return bytes([b ^ key for b in encrypted_data]).decode()

def derive_key(text):
    return hashlib.sha256(text.encode()).digest()

def camellia_encrypt(text, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded_text = padder.update(text.encode()) + padder.finalize()
    encrypted_bytes = iv + encryptor.update(padded_text) + encryptor.finalize()
    return base64.b64encode(encrypted_bytes).decode()

def camellia_decrypt(ciphertext, key):
    encrypted_bytes = base64.b64decode(ciphertext)
    iv, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:]
    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_text = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted_text.decode()

def year_encrypt(text, year):
    encrypted_list = [ord(c) + year for c in text]
    return encrypted_list

def year_decrypt(encrypted_list, year):
    decrypted_text = "".join(chr(num - year) for num in encrypted_list)
    return decrypted_text

# Generar claves RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

private_key, public_key = generate_rsa_keys()

# Leer el texto
with open("texto.txt", "r", encoding="utf-8") as f:
    input_text = f.read()

# Configuración de métodos

key_text = "clave_de_prueba"
key = derive_key(key_text)
iterations = 100



methods = {
    "AES": (aes_encrypt, aes_decrypt),
    "Fernet": (fernet_encrypt, fernet_decrypt),
    "RSA": (rsa_encrypt, rsa_decrypt),
    "XOR": (xor_encrypt, xor_decrypt),
    "Camellia": (lambda text: camellia_encrypt(text, key), lambda data: camellia_decrypt(data, key)),
    "Year Encryption": (lambda text: year_encrypt(text, 2001), lambda data: year_decrypt(data, 2001))
}

# Función para actualizar la tabla
def update_table(results):
    sorted_results = {k: v for k, v in results.items() if "Time (s)" in v}

    sorted_time = sorted(sorted_results.items(), key=lambda x: x[1]['Time (s)'])
    sorted_cpu = sorted(sorted_results.items(), key=lambda x: x[1]['CPU Time (s)'])
    sorted_memory = sorted(sorted_results.items(), key=lambda x: x[1]['Memory (bytes)'])

    rankings = {
        method: {
            "R. Tiempo": sorted_time.index((method, results[method])) + 1,
            "R. CPU": sorted_cpu.index((method, results[method])) + 1,
            "R. Memoria": sorted_memory.index((method, results[method])) + 1
        }
        for method in sorted_results
    }

    for row in table.get_children():
        table.delete(row)

    for method, metrics in results.items():
        if "Error" in metrics:
            table.insert("", "end", values=(method, "Error", "Error", "Error", "-", "-", "-"))
        else:
            table.insert("", "end", values=(
                method,
                metrics['Time (s)'],
                metrics['CPU Time (s)'],
                metrics['Memory (bytes)'],
                rankings[method]['R. Tiempo'],
                rankings[method]['R. CPU'],
                rankings[method]['R. Memoria']
            ))


# Función para ejecutar el benchmark
def run_benchmark():
    btn_run.config(state=tk.DISABLED)
    progress["value"] = 0
    progress["maximum"] = len(methods)
    
    results = {}

    for i, (method_name, (encrypt, decrypt)) in enumerate(methods.items()):
        try:
            print(f"[LOG] Ejecutando método: {method_name}")
            results[method_name] = measure_performance(encrypt, decrypt, input_text, iterations, method_name)
        except Exception as e:
            results[method_name] = {"Error": str(e)}
        
        progress["value"] = i + 1
        root.update_idletasks()

    update_table(results)
    btn_run.config(state=tk.NORMAL)

# Interfaz gráfica
root = tk.Tk()
root.title("Benchmark de Encriptación")
root.geometry("900x450")

frame = tk.Frame(root)
frame.pack(pady=10)

btn_run = tk.Button(frame, text="Ejecutar Benchmark", command=lambda: threading.Thread(target=run_benchmark, daemon=True).start(), font=("Arial", 12))
btn_run.pack()

progress = ttk.Progressbar(root, orient="horizontal", length=600, mode="determinate")
progress.pack(pady=10)

columns = ("Método", "Tiempo (s)", "CPU (s)", "Memoria (bytes)", "R. Tiempo", "R. CPU", "R. Memoria")
table = ttk.Treeview(root, columns=columns, show="headings", height=10)

for col in columns:
    table.heading(col, text=col)
    table.column(col, anchor="center", width=120)

table.pack(pady=10)

root.mainloop()
