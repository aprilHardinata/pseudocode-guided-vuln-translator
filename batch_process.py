import json
import ollama

# 1. Load data sampel MegaVul
with open("sample_megavul.json", "r") as f:
  data = json.load(f)

results = []
total_samples = len(data)

print(f"=== MEMULAI BATCH PROCESSING ({total_samples} SAMPEL CVE) ===\n")

for idx, sample in enumerate(data, start=1):
  cve_id = sample.get("cve_id") or f"CVE-Sample-{idx}"
  cwe_id = sample.get("cwe_id") or "CWE-Unknown"
  kode_c = sample.get("vulnerable_code") or ""

  if not kode_c.strip():
    print(f"[{idx}/{total_samples}] {cve_id} -> DILEWATI (Kode C kosong)")
    continue

  print(f"[{idx}/{total_samples}] Memproses {cve_id} (Label: {cwe_id})...")

  # Tahap 1: Ekstraksi Pseudocode (Jembatan Semantik)
  prompt_1 = f"""
Ubah kode C/C++ berikut menjadi pseudocode yang mengunci logika semantik dan alur variabelnya:
{kode_c}
"""
  resp_1 = ollama.generate(model="qwen2.5-coder:7b", prompt=prompt_1)
  pseudocode = resp_1.get("response", "")

  # Tahap 2: Translasi ke Python & Anotasi CWE
  prompt_2 = f"""
Gunakan pseudocode berikut sebagai panduan utama:
{pseudocode}

Referensikan juga kode asli C ini:
{kode_c}

Berdasarkan label kerentanan {cwe_id}:
1. Terjemahkan logika kode di atas ke dalam bahasa Python.
2. Tunjukkan dan soroti baris kode Python yang rentan.
3. Jelaskan alasan teknisnya secara singkat mengapa baris tersebut rentan.
"""
  resp_2 = ollama.generate(model="qwen2.5-coder:7b", prompt=prompt_2)
  hasil_final = resp_2.get("response", "")

  # Simpan hasil per sampel
  results.append({
      "sample_index": idx,
      "cve_id": cve_id,
      "cwe_id": cwe_id,
      "original_c_code": kode_c,
      "pseudocode": pseudocode,
      "python_translation_and_annotation": hasil_final,
  })
  print(f"    -> [OK] Selesai diproses.")

# 2. Simpan seluruh luaran ke berkas JSON
output_file = "hasil_eksekusi_megavul.json"
with open(output_file, "w", encoding="utf-8") as f:
  json.dump(results, f, indent=2, ensure_ascii=False)

print("\n==================================================")
print(f"✅ BATCH SELESAI! Hasil disimpan di '{output_file}'.")