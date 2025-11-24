#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <chrono>
#include <ctime>
#include <algorithm>

#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oaep.h>
#include <cryptopp/sha.h>
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <cryptopp/queue.h>

using namespace CryptoPP;

// ---------- Utility: file I/O ----------

std::string read_file_binary(const std::string &path)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs)
        throw std::runtime_error("Cannot open file for reading: " + path);
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

void write_file_binary(const std::string &path, const std::string &data)
{
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs)
        throw std::runtime_error("Cannot open file for writing: " + path);
    ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
}

std::string read_file_text(const std::string &path)
{
    std::ifstream ifs(path);
    if (!ifs)
        throw std::runtime_error("Cannot open file for reading: " + path);
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

void write_file_text(const std::string &path, const std::string &data)
{
    std::ofstream ofs(path);
    if (!ofs)
        throw std::runtime_error("Cannot open file for writing: " + path);
    ofs << data;
}

// ---------- Utility: time ----------

std::string now_iso8601_utc()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t t = system_clock::to_time_t(now);
    std::tm gm{};
#if defined(_WIN32)
    gmtime_s(&gm, &t);
#else
    gmtime_r(&t, &gm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &gm);
    return std::string(buf);
}

// ---------- Utility: encoding (base64, hex) ----------

std::string encode_base64(const std::string &bin)
{
    std::string out;
    StringSource ss(reinterpret_cast<const byte *>(bin.data()), bin.size(), true,
                    new Base64Encoder(new StringSink(out), false)); // no line breaks
    return out;
}

std::string decode_base64(const std::string &b64)
{
    std::string out;
    StringSource ss(b64, true,
                    new Base64Decoder(new StringSink(out)));
    return out;
}

std::string encode_hex(const std::string &bin)
{
    std::string out;
    StringSource ss(reinterpret_cast<const byte *>(bin.data()), bin.size(), true,
                    new HexEncoder(new StringSink(out), false)); // uppercase=false
    return out;
}

std::string decode_hex(const std::string &hex)
{
    std::string out;
    StringSource ss(hex, true,
                    new HexDecoder(new StringSink(out)));
    return out;
}

// ---------- Utility: small JSON helpers (very simple) ----------

// NOTE: đây KHÔNG phải JSON parser đầy đủ, chỉ đủ dùng với format ta tạo ra.

std::string json_get_string(const std::string &json, const std::string &key)
{
    std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos)
        throw std::runtime_error("JSON key not found: " + key);
    pos = json.find(':', pos);
    if (pos == std::string::npos)
        throw std::runtime_error("Invalid JSON around key: " + key);
    pos = json.find('"', pos);
    if (pos == std::string::npos)
        throw std::runtime_error("Invalid JSON string for key: " + key);
    size_t start = pos + 1;
    size_t end = json.find('"', start);
    if (end == std::string::npos)
        throw std::runtime_error("Invalid JSON string for key: " + key);
    return json.substr(start, end - start);
}

int json_get_int(const std::string &json, const std::string &key)
{
    std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos)
        throw std::runtime_error("JSON key not found: " + key);
    pos = json.find(':', pos);
    if (pos == std::string::npos)
        throw std::runtime_error("Invalid JSON around key: " + key);
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\n' || json[pos] == '\t'))
        ++pos;
    bool neg = false;
    if (pos < json.size() && json[pos] == '-')
    {
        neg = true;
        ++pos;
    }
    int val = 0;
    while (pos < json.size() && std::isdigit(static_cast<unsigned char>(json[pos])))
    {
        val = val * 10 + (json[pos] - '0');
        ++pos;
    }
    return neg ? -val : val;
}

// ---------- RSA key save/load (PEM) ----------

std::string der_from_public(const RSA::PublicKey &pub)
{
    ByteQueue queue;
    pub.Save(queue);
    std::string der;
    der.resize(queue.CurrentSize());
    queue.Get(reinterpret_cast<byte *>(&der[0]), der.size());
    return der;
}

std::string der_from_private(const RSA::PrivateKey &priv)
{
    ByteQueue queue;
    priv.Save(queue);
    std::string der;
    der.resize(queue.CurrentSize());
    queue.Get(reinterpret_cast<byte *>(&der[0]), der.size());
    return der;
}

void save_pem_public(const RSA::PublicKey &pub, const std::string &path)
{
    std::string der = der_from_public(pub);
    std::string b64 = encode_base64(der);

    std::ostringstream oss;
    oss << "-----BEGIN PUBLIC KEY-----\n";
    // chia dòng 64 chars (optional)
    for (size_t i = 0; i < b64.size(); i += 64)
    {
        oss << b64.substr(i, 64) << "\n";
    }
    oss << "-----END PUBLIC KEY-----\n";

    write_file_text(path, oss.str());
}

void save_pem_private(const RSA::PrivateKey &priv, const std::string &path)
{
    std::string der = der_from_private(priv);
    std::string b64 = encode_base64(der);

    std::ostringstream oss;
    oss << "-----BEGIN PRIVATE KEY-----\n";
    for (size_t i = 0; i < b64.size(); i += 64)
    {
        oss << b64.substr(i, 64) << "\n";
    }
    oss << "-----END PRIVATE KEY-----\n";

    write_file_text(path, oss.str());
}

std::string extract_pem_body_base64(const std::string &pem, const std::string &header, const std::string &footer)
{
    size_t h = pem.find(header);
    size_t f = pem.find(footer);
    if (h == std::string::npos || f == std::string::npos || f <= h)
    {
        throw std::runtime_error("Invalid PEM format");
    }
    h += header.size();
    std::string body = pem.substr(h, f - h);
    std::string out;
    out.reserve(body.size());
    for (char c : body)
    {
        if (c != '\r' && c != '\n' && c != ' ' && c != '\t')
        {
            out.push_back(c);
        }
    }
    return out;
}

RSA::PublicKey load_public_pem(const std::string &path)
{
    std::string pem = read_file_text(path);
    std::string b64 = extract_pem_body_base64(pem, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----");
    std::string der = decode_base64(b64);

    ByteQueue queue;
    queue.Put(reinterpret_cast<const byte *>(der.data()), der.size());
    queue.MessageEnd();

    RSA::PublicKey pub;
    pub.Load(queue);
    return pub;
}

RSA::PrivateKey load_private_pem(const std::string &path)
{
    std::string pem = read_file_text(path);
    std::string b64 = extract_pem_body_base64(pem, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
    std::string der = decode_base64(b64);

    ByteQueue queue;
    queue.Put(reinterpret_cast<const byte *>(der.data()), der.size());
    queue.MessageEnd();

    RSA::PrivateKey priv;
    priv.Load(queue);
    return priv;
}

// ---------- AES-GCM helper ----------

struct AesGcmCiphertext
{
    std::string iv;         // 12 bytes
    std::string cipher_tag; // ciphertext + tag
};

AesGcmCiphertext aes_gcm_encrypt(
    const std::string &key,
    const std::string &plaintext,
    const std::string &aad)
{
    if (key.size() != 32)
        throw std::runtime_error("AES-GCM key must be 32 bytes (AES-256)");

    AutoSeededRandomPool rng;

    AesGcmCiphertext out;
    out.iv.resize(12);
    rng.GenerateBlock(reinterpret_cast<byte *>(&out.iv[0]), out.iv.size());

    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(reinterpret_cast<const byte *>(key.data()), key.size(),
                     reinterpret_cast<const byte *>(out.iv.data()), out.iv.size());

    std::string cipher;
    AuthenticatedEncryptionFilter aef(enc,
                                      new StringSink(cipher),
                                      false, // putAAD=false
                                      16     // tag size
    );

    if (!aad.empty())
    {
        aef.ChannelPut(AAD_CHANNEL, reinterpret_cast<const byte *>(aad.data()), aad.size());
        aef.ChannelMessageEnd(AAD_CHANNEL);
    }

    aef.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte *>(plaintext.data()), plaintext.size());
    aef.ChannelMessageEnd(DEFAULT_CHANNEL);

    out.cipher_tag = cipher;
    return out;
}

std::string aes_gcm_decrypt(
    const std::string &key,
    const AesGcmCiphertext &in,
    const std::string &aad)
{
    if (key.size() != 32)
        throw std::runtime_error("AES-GCM key must be 32 bytes (AES-256)");

    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(reinterpret_cast<const byte *>(key.data()), key.size(),
                     reinterpret_cast<const byte *>(in.iv.data()), in.iv.size());

    std::string recovered;
    try
    {
        AuthenticatedDecryptionFilter adf(dec,
                                          new StringSink(recovered),
                                          AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                                          16);

        if (!aad.empty())
        {
            adf.ChannelPut(AAD_CHANNEL, reinterpret_cast<const byte *>(aad.data()), aad.size());
            adf.ChannelMessageEnd(AAD_CHANNEL);
        }

        adf.ChannelPut(DEFAULT_CHANNEL,
                       reinterpret_cast<const byte *>(in.cipher_tag.data()), in.cipher_tag.size());
        adf.ChannelMessageEnd(DEFAULT_CHANNEL);
    }
    catch (const CryptoPP::Exception &)
    {
        throw std::runtime_error("AES-GCM authentication failed (wrong key/label or tampering)");
    }

    return recovered;
}

// ---------- Envelope JSON (rsa-oaep / hybrid) ----------

std::string build_rsa_oaep_envelope(
    int modulus_bits,
    const std::string &hashName,
    const std::string &label_b64,
    const std::string &payload_enc, // "base64" or "hex"
    const std::string &ciphertext_encoded)
{
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"version\": 1,\n";
    oss << "  \"mode\": \"rsa-oaep\",\n";
    oss << "  \"modulus_bits\": " << modulus_bits << ",\n";
    oss << "  \"hash\": \"" << hashName << "\",\n";
    oss << "  \"label_b64\": \"" << label_b64 << "\",\n";
    oss << "  \"payload_enc\": \"" << payload_enc << "\",\n";
    oss << "  \"ciphertext_" << payload_enc << "\": \"" << ciphertext_encoded << "\"\n";
    oss << "}\n";
    return oss.str();
}

std::string build_hybrid_envelope(
    int modulus_bits,
    const std::string &hashName,
    const std::string &label_b64,
    const std::string &payload_enc, // "base64" or "hex"
    const std::string &iv_b64,
    const std::string &enc_key_encoded,
    const std::string &cipher_encoded)
{
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"version\": 1,\n";
    oss << "  \"mode\": \"hybrid\",\n";
    oss << "  \"modulus_bits\": " << modulus_bits << ",\n";
    oss << "  \"hash\": \"" << hashName << "\",\n";
    oss << "  \"aead_cipher\": \"AES-256-GCM\",\n";
    oss << "  \"tag_len\": 16,\n";
    oss << "  \"iv_b64\": \"" << iv_b64 << "\",\n";
    oss << "  \"label_b64\": \"" << label_b64 << "\",\n";
    oss << "  \"payload_enc\": \"" << payload_enc << "\",\n";
    oss << "  \"enc_key_" << payload_enc << "\": \"" << enc_key_encoded << "\",\n";
    oss << "  \"ciphertext_" << payload_enc << "\": \"" << cipher_encoded << "\"\n";
    oss << "}\n";
    return oss.str();
}

// ---------- CLI helpers ----------

struct Options
{
    std::string command;
    int bits = 3072;

    std::string pub_path;
    std::string priv_path;
    std::string meta_path;

    std::string in_path;
    std::string out_path;
    std::string text_input;
    std::string label;
    std::string encode = "base64";

    // perf
    std::string perf_1k;
    std::string perf_100k;
    std::string perf_1m;

    // CSV output cho perf
    std::string csv_path;
};

void print_usage()
{
    std::cout << "Usage:\n"
                 "  rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem --meta keymeta.json\n"
                 "  rsatool encrypt --pub pub.pem [--in file | --text \"...\"] --out cipher.json [--label \"...\"] [--encode base64|hex]\n"
                 "  rsatool decrypt --priv priv.pem --in cipher.json --out plain.bin [--label \"...\"]\n";
}

Options parse_args(int argc, char *argv[])
{
    if (argc < 2)
        throw std::runtime_error("Missing command");

    Options opt;
    opt.command = argv[1];

    for (int i = 2; i < argc; ++i)
    {
        std::string a = argv[i];
        auto next = [&](std::string &dest)
        {
            if (i + 1 >= argc)
                throw std::runtime_error("Missing value for " + a);
            dest = argv[++i];
        };

        if (a == "--bits")
        {
            std::string s;
            next(s);
            opt.bits = std::stoi(s);
        }
        else if (a == "--pub")
        {
            next(opt.pub_path);
        }
        else if (a == "--priv")
        {
            next(opt.priv_path);
        }
        else if (a == "--meta")
        {
            next(opt.meta_path);
        }
        else if (a == "--in")
        {
            next(opt.in_path);
        }
        else if (a == "--out")
        {
            next(opt.out_path);
        }
        else if (a == "--text")
        {
            next(opt.text_input);
        }
        else if (a == "--label")
        {
            next(opt.label);
        }
        else if (a == "--encode")
        {
            next(opt.encode);
            if (opt.encode != "base64" && opt.encode != "hex")
            {
                std::cerr << "Warning: encode=" << opt.encode << " not supported, using base64.\n";
                opt.encode = "base64";
            }
        }
        else if (a == "--perf-1k")
        {
            next(opt.perf_1k);
        }
        else if (a == "--perf-100k")
        {
            next(opt.perf_100k);
        }
        else if (a == "--perf-1m")
        {
            next(opt.perf_1m);
        }
        else if (a == "--csv")
        {
            next(opt.csv_path);
        }
        else
        {
            throw std::runtime_error("Unknown option: " + a);
        }
    }

    return opt;
}

// ---------- Command: keygen ----------

void cmd_keygen(const Options &opt)
{
    if (opt.pub_path.empty() || opt.priv_path.empty() || opt.meta_path.empty())
    {
        throw std::runtime_error("keygen requires --pub, --priv, --meta");
    }
    if (opt.bits < 2048)
    {
        throw std::runtime_error("RSA bits must be >= 2048; lab requires >= 3072");
    }

    AutoSeededRandomPool rng;

    std::cout << "Generating RSA key " << opt.bits << " bits...\n";
    InvertibleRSAFunction params;
    params.Initialize(rng, opt.bits);

    RSA::PrivateKey priv(params);
    RSA::PublicKey pub(params);

    save_pem_public(pub, opt.pub_path);
    save_pem_private(priv, opt.priv_path);

    int modulus_bits = pub.GetModulus().BitCount();

    std::ostringstream meta;
    meta << "{\n";
    meta << "  \"created_at\": \"" << now_iso8601_utc() << "\",\n";
    meta << "  \"modulus_bits\": " << modulus_bits << ",\n";
    meta << "  \"hash\": \"SHA-256\"\n";
    meta << "}\n";
    write_file_text(opt.meta_path, meta.str());

    std::cout << "Keypair generated.\n";
    std::cout << "  Public key:  " << opt.pub_path << "\n";
    std::cout << "  Private key: " << opt.priv_path << "\n";
    std::cout << "  Metadata:    " << opt.meta_path << "\n";
}

// ---------- Command: encrypt ----------

std::string read_plaintext(const Options &opt)
{
    if (!opt.text_input.empty() && !opt.in_path.empty())
    {
        throw std::runtime_error("Specify either --text or --in, not both");
    }
    if (!opt.text_input.empty())
    {
        return opt.text_input; // UTF-8 as-is
    }
    if (!opt.in_path.empty())
    {
        return read_file_binary(opt.in_path);
    }
    throw std::runtime_error("encrypt requires --text or --in");
}

void cmd_encrypt(const Options &opt)
{
    if (opt.pub_path.empty())
    {
        throw std::runtime_error("encrypt requires --pub");
    }
    if (opt.out_path.empty())
    {
        throw std::runtime_error("encrypt requires --out");
    }

    RSA::PublicKey pub = load_public_pem(opt.pub_path);
    int modulus_bits = pub.GetModulus().BitCount();

    std::string plaintext = read_plaintext(opt);
    std::string label_bytes = opt.label; // UTF-8

    using RSAES_OAEP_SHA256_Enc = RSAES<OAEP<SHA256>>::Encryptor;

    RSAES_OAEP_SHA256_Enc enc(pub);

    size_t max_plain = enc.FixedMaxPlaintextLength();

    AutoSeededRandomPool rng;
    std::string payload_enc = opt.encode; // "base64" hoặc "hex"

    if (plaintext.size() <= max_plain)
    {
        // ----- pure RSA-OAEP -----
        std::string cipher;
        cipher.resize(enc.CiphertextLength(plaintext.size()));

        enc.Encrypt(rng,
                    reinterpret_cast<const byte *>(plaintext.data()), plaintext.size(),
                    reinterpret_cast<byte *>(&cipher[0]));

        std::string cipher_encoded =
            (payload_enc == "base64") ? encode_base64(cipher) : encode_hex(cipher);

        std::string label_b64 = encode_base64(label_bytes);
        std::string json = build_rsa_oaep_envelope(
            modulus_bits,
            "SHA-256",
            label_b64,
            payload_enc,
            cipher_encoded);

        write_file_text(opt.out_path, json);
        std::cout << "Encrypted (rsa-oaep). Output: " << opt.out_path << "\n";
    }
    else
    {
        // ----- hybrid AES-GCM -----
        // Tạo AES-256 key ngẫu nhiên
        std::string aes_key;
        aes_key.resize(32);
        rng.GenerateBlock(reinterpret_cast<byte *>(&aes_key[0]), aes_key.size());

        // AES-GCM encrypt
        AesGcmCiphertext ct = aes_gcm_encrypt(aes_key, plaintext, label_bytes);

        // RSA-OAEP wrap AES key
        std::string wrapped;
        wrapped.resize(enc.CiphertextLength(aes_key.size()));
        enc.Encrypt(rng,
                    reinterpret_cast<const byte *>(aes_key.data()), aes_key.size(),
                    reinterpret_cast<byte *>(&wrapped[0]));

        std::string wrapped_encoded =
            (payload_enc == "base64") ? encode_base64(wrapped) : encode_hex(wrapped);
        std::string cipher_encoded =
            (payload_enc == "base64") ? encode_base64(ct.cipher_tag) : encode_hex(ct.cipher_tag);
        std::string iv_b64 = encode_base64(ct.iv);
        std::string label_b64 = encode_base64(label_bytes);

        std::string json = build_hybrid_envelope(
            modulus_bits,
            "SHA-256",
            label_b64,
            payload_enc,
            iv_b64,
            wrapped_encoded,
            cipher_encoded);

        write_file_text(opt.out_path, json);
        std::cout << "Encrypted (hybrid AES-256-GCM + RSA-OAEP). Output: " << opt.out_path << "\n";
    }
}

// ---------- Command: decrypt ----------

void cmd_decrypt(const Options &opt)
{
    if (opt.priv_path.empty())
    {
        throw std::runtime_error("decrypt requires --priv");
    }
    if (opt.in_path.empty())
    {
        throw std::runtime_error("decrypt requires --in");
    }
    if (opt.out_path.empty())
    {
        throw std::runtime_error("decrypt requires --out");
    }

    RSA::PrivateKey priv = load_private_pem(opt.priv_path);

    std::string env = read_file_text(opt.in_path);

    std::string mode = json_get_string(env, "mode");
    std::string payload_enc = json_get_string(env, "payload_enc");
    if (payload_enc != "base64" && payload_enc != "hex")
    {
        throw std::runtime_error("Unsupported payload_enc in envelope");
    }

    std::string label_b64 = json_get_string(env, "label_b64");
    std::string label_bytes = decode_base64(label_b64);

    // Nếu user cung cấp --label, phải trùng với label trong envelope
    if (!opt.label.empty() && opt.label != label_bytes)
    {
        std::cerr << "Warning: provided --label does not match stored label in envelope.\n";
        // để đơn giản, vẫn dùng label từ envelope (đảm bảo decrypt ok).
    }

    using RSAES_OAEP_SHA256_Dec = RSAES<OAEP<SHA256>>::Decryptor;

    RSAES_OAEP_SHA256_Dec dec(priv);

    if (mode == "rsa-oaep")
    {
        std::string field = "ciphertext_" + payload_enc;
        std::string cipher_encoded = json_get_string(env, field);
        std::string cipher =
            (payload_enc == "base64") ? decode_base64(cipher_encoded) : decode_hex(cipher_encoded);

        std::string recovered;
        recovered.resize(dec.MaxPlaintextLength(cipher.size()));

        AutoSeededRandomPool rng;

        DecodingResult result = dec.Decrypt(
            rng,
            reinterpret_cast<const byte *>(cipher.data()), cipher.size(),
            reinterpret_cast<byte *>(&recovered[0]));

        if (!result.isValidCoding)
        {
            throw std::runtime_error("RSA-OAEP decryption failed (wrong key/label or tampering).");
        }
        recovered.resize(result.messageLength);

        write_file_binary(opt.out_path, recovered);
        std::cout << "Decrypted (rsa-oaep). Plaintext written to: " << opt.out_path << "\n";
    }
    else if (mode == "hybrid")
    {
        std::string iv_b64 = json_get_string(env, "iv_b64");
        std::string iv = decode_base64(iv_b64);

        std::string field_k = "enc_key_" + payload_enc;
        std::string enc_key_encoded = json_get_string(env, field_k);
        std::string enc_key =
            (payload_enc == "base64") ? decode_base64(enc_key_encoded) : decode_hex(enc_key_encoded);

        std::string field_c = "ciphertext_" + payload_enc;
        std::string cipher_encoded = json_get_string(env, field_c);
        std::string cipher_tag =
            (payload_enc == "base64") ? decode_base64(cipher_encoded) : decode_hex(cipher_encoded);

        // RSA-OAEP unwrap AES key
        std::string aes_key;
        aes_key.resize(dec.MaxPlaintextLength(enc_key.size()));

        AutoSeededRandomPool rng;

        DecodingResult result = dec.Decrypt(
            rng,
            reinterpret_cast<const byte *>(enc_key.data()), enc_key.size(),
            reinterpret_cast<byte *>(&aes_key[0]));

        if (!result.isValidCoding)
        {
            throw std::runtime_error("RSA-OAEP unwrap AES key failed (wrong key/label or tampering).");
        }
        aes_key.resize(result.messageLength);

        if (aes_key.size() != 32)
        {
            throw std::runtime_error("Unwrapped AES key size != 32 bytes (corrupted envelope).");
        }

        // AES-GCM decrypt
        AesGcmCiphertext ct;
        ct.iv = iv;
        ct.cipher_tag = cipher_tag;

        std::string recovered = aes_gcm_decrypt(aes_key, ct, label_bytes);
        write_file_binary(opt.out_path, recovered);

        std::cout << "Decrypted (hybrid). Plaintext written to: " << opt.out_path << "\n";
    }
    else
    {
        throw std::runtime_error("Unsupported envelope mode: " + mode);
    }
}

#include <numeric>
#include <cmath>

// Thống kê cho 1 case (1 file)
struct PerfStats
{
    std::string label; // ví dụ: "RSA-OAEP/hybrid 1KB"
    double mean_ms = 0.0;
    double median_ms = 0.0;
    double stddev_ms = 0.0;
    double ci95_low_ms = 0.0;
    double ci95_high_ms = 0.0;
    int blocks = 0;
    int rounds_per_block = 0;
};

PerfStats compute_stats(const std::string &label,
                        const std::vector<double> &samples_ms,
                        int rounds_per_block)
{
    if (samples_ms.empty())
    {
        throw std::runtime_error("No samples for performance stats");
    }

    size_t n = samples_ms.size();
    std::vector<double> s = samples_ms;
    std::sort(s.begin(), s.end());

    double sum = std::accumulate(s.begin(), s.end(), 0.0);
    double mean = sum / static_cast<double>(n);

    double median;
    if (n % 2 == 1)
    {
        median = s[n / 2];
    }
    else
    {
        median = 0.5 * (s[n / 2 - 1] + s[n / 2]);
    }

    double var = 0.0;
    if (n > 1)
    {
        for (double x : s)
        {
            double d = x - mean;
            var += d * d;
        }
        var /= static_cast<double>(n - 1); // sample variance
    }
    double stddev = std::sqrt(var);

    double ci = 0.0;
    if (n > 1)
    {
        // n = số block (thường = 10), dùng t-distribution với df = n-1.
        // Với n = 10 → t_{0.975,9} ≈ 2.262.
        const double t_val = 2.262;
        ci = t_val * stddev / std::sqrt(static_cast<double>(n)); // 95% CI
    }

    PerfStats st;
    st.label = label;
    st.mean_ms = mean;
    st.median_ms = median;
    st.stddev_ms = stddev;
    st.ci95_low_ms = mean - ci;
    st.ci95_high_ms = mean + ci;
    st.blocks = static_cast<int>(n);
    st.rounds_per_block = rounds_per_block;
    return st;
}

PerfStats benchmark_enc_dec_blocked(
    const std::string &case_label,
    const std::string &data,
    RSA::PublicKey &pub,
    RSA::PrivateKey &priv,
    std::vector<double> &block_times_ms, // <-- thêm tham số này
    int warmup_seconds = 2,
    int rounds_per_block = 1000,
    int blocks = 10)
{
    using clock = std::chrono::high_resolution_clock;
    using namespace std::chrono;

    using RSAES_OAEP_SHA256_Enc = RSAES<OAEP<SHA256>>::Encryptor;
    using RSAES_OAEP_SHA256_Dec = RSAES<OAEP<SHA256>>::Decryptor;

    RSAES_OAEP_SHA256_Enc enc(pub);
    RSAES_OAEP_SHA256_Dec dec(priv);

    AutoSeededRandomPool rng;

    size_t max_plain = enc.FixedMaxPlaintextLength();

    auto one_round = [&](AutoSeededRandomPool &rng_local)
    {
        if (data.size() <= max_plain)
        {
            // -------- Pure RSA-OAEP --------
            std::string cipher;
            cipher.resize(enc.CiphertextLength(data.size()));

            enc.Encrypt(rng_local,
                        reinterpret_cast<const byte *>(data.data()), data.size(),
                        reinterpret_cast<byte *>(&cipher[0]));

            std::string recovered;
            recovered.resize(dec.MaxPlaintextLength(cipher.size()));

            DecodingResult result = dec.Decrypt(
                rng_local,
                reinterpret_cast<const byte *>(cipher.data()), cipher.size(),
                reinterpret_cast<byte *>(&recovered[0]));

            if (!result.isValidCoding)
            {
                throw std::runtime_error("RSA-OAEP decrypt failed in perf test (pure).");
            }
            recovered.resize(result.messageLength);
        }
        else
        {
            // -------- Hybrid AES-256-GCM + RSA-OAEP key wrap --------
            std::string aes_key;
            aes_key.resize(32);
            rng_local.GenerateBlock(reinterpret_cast<byte *>(&aes_key[0]), aes_key.size());

            std::string label_bytes; // label rỗng trong perf
            AesGcmCiphertext ct = aes_gcm_encrypt(aes_key, data, label_bytes);

            std::string wrapped;
            wrapped.resize(enc.CiphertextLength(aes_key.size()));
            enc.Encrypt(rng_local,
                        reinterpret_cast<const byte *>(aes_key.data()), aes_key.size(),
                        reinterpret_cast<byte *>(&wrapped[0]));

            std::string unwrapped;
            unwrapped.resize(dec.MaxPlaintextLength(wrapped.size()));
            DecodingResult res = dec.Decrypt(
                rng_local,
                reinterpret_cast<const byte *>(wrapped.data()), wrapped.size(),
                reinterpret_cast<byte *>(&unwrapped[0]));

            if (!res.isValidCoding)
            {
                throw std::runtime_error("RSA-OAEP unwrap AES key failed in perf test (hybrid).");
            }
            unwrapped.resize(res.messageLength);

            if (unwrapped.size() != 32)
            {
                throw std::runtime_error("Unwrapped AES key size != 32 in perf test.");
            }

            AesGcmCiphertext ct2;
            ct2.iv = ct.iv;
            ct2.cipher_tag = ct.cipher_tag;

            std::string recovered = aes_gcm_decrypt(unwrapped, ct2, label_bytes);
            (void)recovered; // không check trong phần timing
        }
    };

    // ---------- Warm-up ----------
    auto warm_start = clock::now();
    while (duration<double>(clock::now() - warm_start).count() < warmup_seconds)
    {
        for (int i = 0; i < rounds_per_block; ++i)
        {
            one_round(rng);
        }
    }

    // ---------- Measurement ----------
    block_times_ms.clear();
    block_times_ms.reserve(blocks);

    for (int b = 0; b < blocks; ++b)
    {
        auto t1 = clock::now();
        for (int i = 0; i < rounds_per_block; ++i)
        {
            one_round(rng);
        }
        auto t2 = clock::now();
        double ms = duration<double, std::milli>(t2 - t1).count();
        block_times_ms.push_back(ms);

        std::cout << "[Perf] " << case_label << " - block " << (b + 1)
                  << "/" << blocks << ": " << ms << " ms (" << rounds_per_block
                  << " rounds enc+dec)\n";
    }

    // Tính stats từ chính vector block_times_ms
    return compute_stats(case_label, block_times_ms, rounds_per_block);
}

void run_perf_for_files(
    const std::string &pub_pem,
    const std::string &priv_pem,
    const std::string &file_1k,
    const std::string &file_100k,
    const std::string &file_1m,
    const std::string &csv_path)
{
    RSA::PublicKey pub = load_public_pem(pub_pem);
    RSA::PrivateKey priv = load_private_pem(priv_pem);

    std::string data_1k = read_file_binary(file_1k);
    std::string data_100k = read_file_binary(file_100k);
    std::string data_1m = read_file_binary(file_1m);

    std::cout << "=== Performance Test (enc+dec, 1000 rounds/block, 10 blocks) ===\n";

    std::vector<double> bt1, bt2, bt3;

    PerfStats s1 = benchmark_enc_dec_blocked("Perf-1KB", data_1k, pub, priv, bt1);
    PerfStats s2 = benchmark_enc_dec_blocked("Perf-100KB", data_100k, pub, priv, bt2);
    PerfStats s3 = benchmark_enc_dec_blocked("Perf-1MB", data_1m, pub, priv, bt3);

    auto print_stats_with_throughput = [](const PerfStats &st, std::size_t data_size)
    {
        std::cout << "\n[Stats] " << st.label << "\n";
        std::cout << "  blocks: " << st.blocks
                  << ", rounds/block: " << st.rounds_per_block << "\n";
        std::cout << "  mean:   " << st.mean_ms << " ms/block\n";
        std::cout << "  median: " << st.median_ms << " ms/block\n";
        std::cout << "  stddev: " << st.stddev_ms << " ms\n";
        std::cout << "  95% CI: [" << st.ci95_low_ms << ", " << st.ci95_high_ms << "] ms\n";
        std::cout << "  per-op approx mean: "
                  << (st.mean_ms / st.rounds_per_block) << " ms/op (enc+dec)\n";

        double bytes_per_block =
            static_cast<double>(st.rounds_per_block) * static_cast<double>(data_size);
        double mean_sec = st.mean_ms / 1000.0;
        double throughput_MBps =
            (bytes_per_block / (1024.0 * 1024.0)) / mean_sec;

        std::cout << "  Throughput (mean, enc+dec): "
                  << throughput_MBps << " MB/s\n";
    };

    print_stats_with_throughput(s1, data_1k.size());
    print_stats_with_throughput(s2, data_100k.size());
    print_stats_with_throughput(s3, data_1m.size());

    // ---------- Ghi CSV kiểu "2 bảng" như hình ----------
    if (!csv_path.empty())
    {
        std::ofstream ofs(csv_path);
        if (!ofs)
        {
            throw std::runtime_error("Cannot write CSV: " + csv_path);
        }

        // BẢNG 1: summary tổng
        ofs << "File,SizeBytes,RoundsPerBlock,Blocks,"
            << "MeanMs,MedianMs,StddevMs,CILowMs,CIHighMs,ThroughputMBps\n";

        auto write_summary_row = [&ofs](const std::string &fileName,
                                        std::size_t sizeBytes,
                                        const PerfStats &st)
        {
            double bytes_per_block =
                static_cast<double>(st.rounds_per_block) * static_cast<double>(sizeBytes);
            double mean_sec = st.mean_ms / 1000.0;
            double throughput_MBps =
                (bytes_per_block / (1024.0 * 1024.0)) / mean_sec;

            ofs << fileName << ","
                << sizeBytes << ","
                << st.rounds_per_block << ","
                << st.blocks << ","
                << st.mean_ms << ","
                << st.median_ms << ","
                << st.stddev_ms << ","
                << st.ci95_low_ms << ","
                << st.ci95_high_ms << ","
                << throughput_MBps << "\n";
        };

        write_summary_row(file_1k, data_1k.size(), s1);
        write_summary_row(file_100k, data_100k.size(), s2);
        write_summary_row(file_1m, data_1m.size(), s3);

        ofs << "\n"; // dòng trống ngăn cách 2 bảng

        // BẢNG 2: chi tiết từng block
        ofs << "Block,File,SizeBytes,RoundsPerBlock,Operation,BlockTimeMs\n";

        auto write_block_rows = [&ofs](const std::string &fileName,
                                       std::size_t sizeBytes,
                                       int rounds_per_block,
                                       const std::vector<double> &block_times)
        {
            for (std::size_t i = 0; i < block_times.size(); ++i)
            {
                ofs << (i + 1) << ","
                    << fileName << ","
                    << sizeBytes << ","
                    << rounds_per_block << ","
                    << "enc+dec" << ","
                    << block_times[i] << "\n";
            }
        };

        write_block_rows(file_1k, data_1k.size(), s1.rounds_per_block, bt1);
        write_block_rows(file_100k, data_100k.size(), s2.rounds_per_block, bt2);
        write_block_rows(file_1m, data_1m.size(), s3.rounds_per_block, bt3);

        std::cout << "\nCSV saved to: " << csv_path << "\n";
    }
}

void cmd_perf(const Options &opt)
{
    if (opt.pub_path.empty() || opt.priv_path.empty())
    {
        throw std::runtime_error("perf requires --pub and --priv");
    }
    if (opt.perf_1k.empty() || opt.perf_100k.empty() || opt.perf_1m.empty())
    {
        throw std::runtime_error("perf requires --perf-1k, --perf-100k, --perf-1m");
    }

    run_perf_for_files(opt.pub_path, opt.priv_path,
                       opt.perf_1k, opt.perf_100k, opt.perf_1m,
                       opt.csv_path);
}
// ---------- main ----------

int main(int argc, char *argv[])
{
    try
    {
        if (argc < 2)
        {
            print_usage();
            return 1;
        }

        Options opt = parse_args(argc, argv);

        if (opt.command == "keygen")
        {
            cmd_keygen(opt);
        }
        else if (opt.command == "encrypt")
        {
            cmd_encrypt(opt);
        }
        else if (opt.command == "decrypt")
        {
            cmd_decrypt(opt);
        }
        else if (opt.command == "perf")
        {
            cmd_perf(opt);
        }
        else
        {
            std::cerr << "Unknown command: " << opt.command << "\n";
            print_usage();
            return 1;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
