# NT219 – Lab 3: RSA-OAEP & Hybrid Encryption (Crypto++)

## Features
RSA key generation (3072–4096 bits)
RSA-OAEP (SHA-256) encryption/decryption
Hybrid mode: AES-256-GCM for large payloads + RSA-OAEP key wrapping
JSON envelope format (self-describing)
Base64/Hex encoding options
Negative test protections:
wrong key
wrong label (AAD)
tampered ciphertext/tag
invalid PEM
Performance benchmarking:
warm-up 1–2s
1000 rounds/block
10 blocks
output to CSV (summary + block-level)
Cross-platform, UTF-8 CLI
# genkey
./rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem --meta keymeta.json

# encrypt
./rsatool encrypt  
  --pub pub.pem  
  --in plain.txt  
  --out cipher.json  
  --label "lab3-label"  
  --encode base64

# decrypt
./rsatool decrypt  
  --priv priv.pem  
  --in cipher.json  
  --out plain_out.txt

# perf
./rsatool perf 
  --pub pub.pem 
  --priv priv.pem 
  --perf-1k 1kb.bin 
  --perf-100k 100kb.bin 
  --perf-1m 1mb.bin 
  --csv rsa_perf.csv

