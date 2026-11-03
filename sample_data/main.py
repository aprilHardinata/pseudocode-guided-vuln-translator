import json
import ollama

# 1. Buka sampel data MegaVul lokal
with open("sample_megavul.json", "r") as f:
  data = json.load(f)

# Ambil sampel pertama
sample = data[0]

# Ambil model llm yang akan digunakan
MODEL_NAME = "qwen2.5-coder:7b"

# Mengambil kode C dan label CWE menggunakan key yang tepat
kode_c = sample.get("vulnerable_code", "")
label_cwe = sample.get("cwe_id", "CWE-Unknown")
cve_id = sample.get("cve_id", "Unknown CVE")

print(f"=== DATA SAMPEL ({cve_id}) ===")
print(f"CWE Label : {label_cwe}")
print(f"Status    : [OK] Kode C berhasil dibaca ({len(kode_c)} karakter)\n")
print("Potongan Kode C Asli:")
print(kode_c[:300] + "\n...\n")
print("=" * 50 + "\n")

# 2. PROMPT TAHAP 1: Ekstraksi Pseudocode (Jembatan Semantik)
prompt_1 = f"""
Ubah kode C/C++ berikut menjadi pseudocode yang mengunci logika semantik dan alur variabelnya:
{kode_c}
"""

print("--- [TAHAP 1] Memproses Ekstraksi Pseudocode ---")
response_1 = ollama.generate(model=MODEL_NAME, prompt=prompt_1)
pseudocode = response_1["response"]

print("\n[HASIL PSEUDOCODE]:")
print(pseudocode)
print("\n" + "=" * 50 + "\n")

# 3. PROMPT TAHAP 2: Translasi ke Python & Anotasi CWE
prompt_2 = f"""
Gunakan pseudocode berikut sebagai panduan utama:
{pseudocode}

Referensikan juga kode asli C ini:
{kode_c}

Berdasarkan label kerentanan {label_cwe}:
1. Terjemahkan logika kode di atas ke dalam bahasa Python.
2. Tunjukkan dan soroti baris kode Python yang rentan.
3. Jelaskan alasan teknisnya secara singkat mengapa baris tersebut rentan.
"""

print("--- [TAHAP 2] Memproses Translasi ke Python & Anotasi ---")
response_2 = ollama.generate(model="qwen2.5-coder:7b", prompt=prompt_2)

print("\n[HASIL TRANSLASI & ANOTASI FINAL]:")
print(response_2["response"])