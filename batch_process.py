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
Extract a clear, semantics-preserving pseudocode from the following C/C++ code.
Focus on locking variable flows, memory control, and logical conditions:

{kode_c}
"""
  
  resp_1 = ollama.generate(model="qwen2.5-coder:7b", prompt=prompt_1)
  pseudocode = resp_1.get("response", "")

  # Tahap 2: Translasi ke Python & Anotasi CWE
  prompt_2 = f"""
Use the following pseudocode as your primary guide:
{pseudocode}

Refer to the original C code for reference:
{kode_c}

Based on the vulnerability label {cwe_id}:
1. Translate the code logic accurately into Python.
2. Highlight the vulnerable line(s) in the Python code.
3. Explain the technical root cause briefly.

IMPORTANT: Provide the technical explanation and vulnerability reasoning in Indonesian.
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