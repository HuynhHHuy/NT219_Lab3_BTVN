# NT219_Lab3_BTVN
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

