/**
 * Bitcoin Puzzle 71 - Ultra-Fast C/C++ Solver & Pool Client
 *
 * Optimized conversion of Python puzzle_hope.pyz / quoc1506/puzzle71
 * Features:
 *   - Elliptic curve point addition (P + G) instead of repeated scalar multiplication
 *   - Native 128-bit integer math for 71-bit keyspace
 *   - Multi-threaded worker pool with atomic progress monitoring
 *   - Direct Base58Check target pre-decoding (20-byte hash160 compare)
 *   - Single-block SHA256 & RIPEMD160 integration
 *   - Full compatibility with puzzle_server.php API (GET range, POST result)
 *   - Standalone range scanner, benchmark mode, and keyspace analyzer
c++ -O3 -std=c++17 -pthread -I/usr/local/opt/secp256k1/include -o puzzle71_solver puzzle71_solver.cpp -L/usr/local/opt/secp256k1/lib -lsecp256k1 -lcurl -lssl -lcrypto -lpthread
 */

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstring>
#include <csignal>
#include <cstdint>
#include <ctime>

#include <curl/curl.h>
#include <secp256k1.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

// Disable deprecated warnings for RIPEMD160 in OpenSSL 3.0
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static std::atomic<bool> g_running(true);

void sigint_handler(int signum) {
    (void)signum;
    g_running = false;
    std::cout << "\n[!] Termination requested. Finishing current task safely...\n";
}

// ---------------------------------------------------------------------------
// 128-bit Unsigned Integer Utilities (Puzzle 71 uses 71-bit integers)
// ---------------------------------------------------------------------------
typedef __uint128_t u128;

u128 parse_u128(const std::string& str) {
    u128 res = 0;
    for (char c : str) {
        if (c >= '0' && c <= '9') {
            res = res * 10 + (c - '0');
        }
    }
    return res;
}

u128 parse_u128_hex(const std::string& str) {
    u128 res = 0;
    for (char c : str) {
        if (c >= '0' && c <= '9') {
            res = (res << 4) | (c - '0');
        } else if (c >= 'a' && c <= 'f') {
            res = (res << 4) | (c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            res = (res << 4) | (c - 'A' + 10);
        }
    }
    return res;
}

std::string u128_to_dec(u128 v) {
    if (v == 0) return "0";
    std::string s;
    while (v > 0) {
        s.push_back('0' + (int)(v % 10));
        v /= 10;
    }
    std::reverse(s.begin(), s.end());
    return s;
}

std::string u128_to_hex64(u128 v) {
    char buf[65];
    snprintf(buf, sizeof(buf), "%016llx%016llx",
             (unsigned long long)(v >> 64),
             (unsigned long long)(v & 0xFFFFFFFFFFFFFFFFULL));
    std::string s(32, '0');
    return s + buf;
}

// Format integer with commas: 4,194,304
std::string format_commas(uint64_t n) {
    std::string s = std::to_string(n);
    int insertPosition = (int)s.length() - 3;
    while (insertPosition > 0) {
        s.insert(insertPosition, ",");
        insertPosition -= 3;
    }
    return s;
}

// ---------------------------------------------------------------------------
// Base58Check Decoder & Encoder
// ---------------------------------------------------------------------------
static const char* B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool b58check_decode_hash160(const std::string& addr, uint8_t hash160_out[20]) {
    std::vector<uint8_t> bytes;
    for (char c : addr) {
        const char* p = strchr(B58_CHARS, c);
        if (!p) return false;
        int val = p - B58_CHARS;
        int carry = val;
        for (size_t i = 0; i < bytes.size(); ++i) {
            int cur = bytes[i] * 58 + carry;
            bytes[i] = cur & 0xFF;
            carry = cur >> 8;
        }
        while (carry > 0) {
            bytes.push_back(carry & 0xFF);
            carry >>= 8;
        }
    }
    for (char c : addr) {
        if (c == '1') bytes.push_back(0);
        else break;
    }
    std::reverse(bytes.begin(), bytes.end());
    if (bytes.size() != 25) return false;

    // Checksum verification
    uint8_t sha1[32], sha2[32];
    SHA256(bytes.data(), 21, sha1);
    SHA256(sha1, 32, sha2);
    if (memcmp(sha2, bytes.data() + 21, 4) != 0) return false;

    memcpy(hash160_out, bytes.data() + 1, 20);
    return true;
}

std::string b58check_encode(uint8_t version, const uint8_t hash160[20]) {
    uint8_t data[25];
    data[0] = version;
    memcpy(data + 1, hash160, 20);
    uint8_t sha1[32], sha2[32];
    SHA256(data, 21, sha1);
    SHA256(sha1, 32, sha2);
    memcpy(data + 21, sha2, 4);

    int leading_zeros = 0;
    while (leading_zeros < 25 && data[leading_zeros] == 0) leading_zeros++;

    std::vector<uint8_t> digits;
    for (int i = 0; i < 25; ++i) {
        int carry = data[i];
        for (size_t j = 0; j < digits.size(); ++j) {
            int cur = digits[j] * 256 + carry;
            digits[j] = cur % 58;
            carry = cur / 58;
        }
        while (carry > 0) {
            digits.push_back(carry % 58);
            carry /= 58;
        }
    }

    std::string result(leading_zeros, '1');
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        result.push_back(B58_CHARS[*it]);
    }
    return result;
}

// ---------------------------------------------------------------------------
// HTTP Libcurl Utilities
// ---------------------------------------------------------------------------
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string http_get(const std::string& url, long timeout_sec = 30) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";
    std::string readBuffer;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_sec);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "puzzle-hope-cpp/2.0");
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK) return "";
    return readBuffer;
}

bool http_post(const std::string& url, const std::string& json_data, std::string* response_out = nullptr, long timeout_sec = 30) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    std::string responseBuffer;
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_sec);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "puzzle-hope-cpp/2.0");

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (res == CURLE_OK && response_out) {
        *response_out = responseBuffer;
    }
    return (res == CURLE_OK);
}

// ---------------------------------------------------------------------------
// Lightweight JSON Extractor
// ---------------------------------------------------------------------------
std::string json_get_string(const std::string& json, const std::string& key) {
    std::string pattern = "\"" + key + "\":";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return "";
    pos += pattern.length();
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    if (pos >= json.length()) return "";

    if (json[pos] == '"') {
        pos++;
        size_t end = json.find('"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    } else {
        size_t end = pos;
        while (end < json.length() && json[end] != ',' && json[end] != '}' && json[end] != ']' && json[end] != '\n' && json[end] != '\r') {
            end++;
        }
        return json.substr(pos, end - pos);
    }
}

int64_t json_get_int(const std::string& json, const std::string& key, int64_t def = 0) {
    std::string s = json_get_string(json, key);
    if (s.empty()) return def;
    try {
        return std::stoll(s);
    } catch (...) {
        return def;
    }
}

// ---------------------------------------------------------------------------
// Range Struct
// ---------------------------------------------------------------------------
struct RangeInfo {
    int puzzle;
    int64_t block;
    int range_idx;
    u128 start;
    u128 end;
    uint64_t range_size;
    std::string target_address;
    int version_byte;
    u128 lower;
    u128 total;
    int64_t total_blocks;
    int64_t ranges_per_block;
};

bool parse_range_json(const std::string& json, RangeInfo& rng) {
    if (json.empty() || json.find("\"start\"") == std::string::npos) return false;
    rng.puzzle = (int)json_get_int(json, "puzzle", 71);
    rng.block = json_get_int(json, "block", 0);
    rng.range_idx = (int)json_get_int(json, "range_idx", 0);
    rng.start = parse_u128(json_get_string(json, "start"));
    rng.end = parse_u128(json_get_string(json, "end"));
    rng.range_size = (uint64_t)json_get_int(json, "range_size", 0);
    rng.target_address = json_get_string(json, "target_address");
    rng.version_byte = (int)json_get_int(json, "version_byte", 0);
    rng.lower = parse_u128(json_get_string(json, "lower"));
    rng.total = parse_u128(json_get_string(json, "total"));
    rng.total_blocks = json_get_int(json, "total_blocks", 0);
    rng.ranges_per_block = json_get_int(json, "ranges_per_block", 0);
    return (!rng.target_address.empty() && rng.end > rng.start);
}

// ---------------------------------------------------------------------------
// ISO Timestamp Helper
// ---------------------------------------------------------------------------
std::string get_iso_timestamp() {
    time_t now = time(nullptr);
    tm* gmt = gmtime(&now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmt);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// Core Worker Thread: Scans [chunk_start, chunk_end) using EC point addition
// ---------------------------------------------------------------------------
void scan_worker(
    u128 chunk_start,
    u128 chunk_end,
    const uint8_t target_hash160[20],
    const uint64_t target_h64_first,
    std::atomic<bool>& found_flag,
    u128& found_key,
    std::mutex& found_mtx,
    std::atomic<uint64_t>& checked_counter
) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ctx) return;

    // 1. Create pubkey for G (scalar 1)
    uint8_t priv_one[32] = {0};
    priv_one[31] = 1;
    secp256k1_pubkey G_pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &G_pubkey, priv_one)) {
        secp256k1_context_destroy(ctx);
        return;
    }

    // 2. Compute initial starting pubkey: P0 = chunk_start * G
    uint8_t priv_start[32] = {0};
    for (int i = 0; i < 16; ++i) {
        priv_start[31 - i] = (uint8_t)(chunk_start >> (i * 8));
    }
    secp256k1_pubkey cur_pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &cur_pubkey, priv_start)) {
        secp256k1_context_destroy(ctx);
        return;
    }

    uint8_t serialized[33];
    size_t ser_len = 33;
    uint8_t sha[32];
    uint8_t h160[20];

    const secp256k1_pubkey* add_inputs[2] = {&cur_pubkey, &G_pubkey};
    secp256k1_pubkey next_pubkey;

    uint64_t local_counter = 0;
    u128 cur_key = chunk_start;

    while (cur_key < chunk_end && !found_flag.load(std::memory_order_relaxed) && g_running.load(std::memory_order_relaxed)) {
        // Serialize compressed pubkey (33 bytes)
        ser_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, serialized, &ser_len, &cur_pubkey, SECP256K1_EC_COMPRESSED);

        // Hash160: RIPEMD160(SHA256(pubkey))
        SHA256(serialized, 33, sha);
        RIPEMD160(sha, 32, h160);

        // Fast 64-bit comparison first for speed (99.99999999% early rejection)
        if (*(const uint64_t*)h160 == target_h64_first) {
            if (memcmp(h160 + 8, target_hash160 + 8, 12) == 0) {
                {
                    std::lock_guard<std::mutex> lk(found_mtx);
                    found_key = cur_key;
                }
                found_flag.store(true, std::memory_order_release);
                break;
            }
        }

        // Advance to next key: P_next = P + G
        if (secp256k1_ec_pubkey_combine(ctx, &next_pubkey, add_inputs, 2)) {
            cur_pubkey = next_pubkey;
        } else {
            // Recompute from scalar if combine ever encounters infinity
            cur_key++;
            local_counter++;
            u128 next_val = cur_key;
            for (int i = 0; i < 16; ++i) {
                priv_start[31 - i] = (uint8_t)(next_val >> (i * 8));
            }
            (void)secp256k1_ec_pubkey_create(ctx, &cur_pubkey, priv_start);
            continue;
        }

        cur_key++;
        local_counter++;

        // Batch atomic flush every 8192 keys to minimize cache coherency overhead
        if ((local_counter & 0x1FFF) == 0) {
            checked_counter.fetch_add(8192, std::memory_order_relaxed);
        }
    }

    uint64_t remainder = local_counter & 0x1FFF;
    if (remainder > 0) {
        checked_counter.fetch_add(remainder, std::memory_order_relaxed);
    }

    secp256k1_context_destroy(ctx);
}

// ---------------------------------------------------------------------------
// Scan an entire range using multi-threading
// ---------------------------------------------------------------------------
bool scan_range(
    int puzzle_id,
    int64_t block_id,
    int range_idx,
    u128 start,
    u128 end,
    const RangeInfo& rng,
    const std::string& user,
    int workers,
    const std::string& api_base
) {
    uint8_t target_h160[20];
    if (!b58check_decode_hash160(rng.target_address, target_h160)) {
        std::cerr << "[!] Error: Invalid target address Base58 checksum: " << rng.target_address << "\n";
        return false;
    }

    uint64_t target_h64_first = *(const uint64_t*)target_h160;
    u128 total_keys = end - start;
    if (total_keys == 0) return false;

    int num_threads = workers;
    if (num_threads <= 0) num_threads = 1;
    if ((u128)num_threads > total_keys) num_threads = (int)total_keys;

    u128 chunk_size = (total_keys + num_threads - 1) / num_threads;

    std::atomic<bool> found_flag(false);
    u128 found_key = 0;
    std::mutex found_mtx;
    std::atomic<uint64_t> checked_counter(0);

    std::vector<std::thread> pool;
    pool.reserve(num_threads);

    auto t_start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < num_threads; ++i) {
        u128 cs = start + i * chunk_size;
        u128 ce = std::min(start + (i + 1) * chunk_size, end);
        if (cs < ce) {
            pool.emplace_back(
                scan_worker,
                cs,
                ce,
                target_h160,
                target_h64_first,
                std::ref(found_flag),
                std::ref(found_key),
                std::ref(found_mtx),
                std::ref(checked_counter)
            );
        }
    }

    for (auto& th : pool) {
        if (th.joinable()) th.join();
    }

    auto t_end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(t_end - t_start).count();
    if (elapsed <= 0.0) elapsed = 0.0001;

    uint64_t total_checked = checked_counter.load();
    double speed = (double)total_checked / elapsed;

    bool hit = found_flag.load();
    u128 key = found_key;

    std::string status = hit ? "found" : "done";

    std::cout << "[*] Range " << block_id << ":" << range_idx 
              << " completed in " << std::fixed << std::setprecision(2) << elapsed << "s "
              << "(" << format_commas((uint64_t)speed) << " keys/s)";

    // Report result to server if api_base provided
    if (!api_base.empty()) {
        std::stringstream json;
        json << "{"
             << "\"action\":\"result\","
             << "\"puzzle\":" << puzzle_id << ","
             << "\"block\":" << block_id << ","
             << "\"range_idx\":" << range_idx << ","
             << "\"status\":\"" << status << "\","
             << "\"private_key\":\"" << (hit ? u128_to_hex64(key) : "") << "\","
             << "\"address\":\"" << (hit ? rng.target_address : "") << "\","
             << "\"position\":\"" << (hit ? u128_to_dec(key - rng.lower + 1) : "") << "\","
             << "\"total\":\"" << u128_to_dec(rng.total) << "\","
             << "\"elapsed\":" << std::fixed << std::setprecision(4) << elapsed << ","
             << "\"user\":\"" << user << "\","
             << "\"speed\":" << std::fixed << std::setprecision(1) << speed << ","
             << "\"timestamp\":\"" << get_iso_timestamp() << "\""
             << "}";

        std::string pool_resp;
        bool submitted = false;
        for (int attempt = 0; attempt < 3; ++attempt) {
            if (http_post(api_base, json.str(), &pool_resp)) {
                submitted = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        if (submitted) {
            std::cout << "[✓] Pool Server Ack: " << pool_resp << "\n";
        } else {
            std::cout << "[!] Warning: Failed to submit result to pool server after 3 attempts\n";
        }
    }

    return hit;
}

// ---------------------------------------------------------------------------
// Keyspace Analysis Mode
// ---------------------------------------------------------------------------
void run_analysis(const RangeInfo& rng) {
    u128 total_keys = rng.total;
    u128 lower = rng.lower;
    u128 upper = lower + total_keys;

    int bits = 0;
    u128 tmp = upper;
    while (tmp > 0) { bits++; tmp >>= 1; }
    bits -= 1;

    std::cout << "======================================================================\n"
              << "  PUZZLE " << rng.puzzle << " - C/C++ HIGH-SPEED SOLVER ANALYSIS\n"
              << "======================================================================\n"
              << "  Target address : " << rng.target_address << "\n"
              << "  Address type   : P2PKH legacy (version 0x" << std::hex << rng.version_byte << std::dec << ")\n"
              << "  Range (Dec)    : [" << u128_to_dec(lower) << ", " << u128_to_dec(upper) << ")\n"
              << "  Total keys     : " << u128_to_dec(total_keys) << " (~2^" << bits << ")\n"
              << "  Keys / range   : " << format_commas(rng.range_size) << "\n"
              << "  Total blocks   : " << rng.total_blocks << "\n"
              << "  Ranges / block : " << rng.ranges_per_block << "\n"
              << "  Engine backend : C++20 + libsecp256k1 (Point Addition P+G)\n\n"
              << "  TIME ESTIMATION PER RANGE (" << format_commas(rng.range_size) << " keys)\n"
              << "  --------------------------------------------------------------------\n";

    struct SpeedEstimate {
        uint64_t rate;
        const char* desc;
    } benchmarks[] = {
        {80000ULL, "Python pure / coincurve (Original baseline)"},
        {600000ULL, "C++ Single Thread (libsecp256k1 Point Addition)"},
        {4000000ULL, "C++ Multi-Core (8 CPU threads)"},
        {16000000ULL, "C++ Server Multi-Core (32 threads)"},
        {150000000ULL, "Mid-range GPU (NVIDIA RTX 3060)"},
        {1000000000ULL, "High-end GPU / Rig (RTX 4090 / Cluster)"}
    };

    for (const auto& b : benchmarks) {
        double seconds = (double)rng.range_size / b.rate;
        double days = seconds / 86400.0;
        std::cout << "  " << std::setw(14) << format_commas(b.rate) << " keys/s (" << b.desc << ")\n";
        if (seconds < 60.0) {
            std::cout << "               -> " << std::fixed << std::setprecision(2) << seconds << " seconds / range\n";
        } else if (days < 1.0) {
            std::cout << "               -> " << std::fixed << std::setprecision(1) << (seconds / 3600.0) << " hours / range\n";
        } else {
            std::cout << "               -> " << std::fixed << std::setprecision(1) << days << " days / range\n";
        }
    }

    std::cout << "\n  SPEEDUP OVER ORIGINAL PYTHON: ~6x to 50x per CPU core!\n"
              << "======================================================================\n";
}

// ---------------------------------------------------------------------------
// Local Benchmark Mode
// ---------------------------------------------------------------------------
void run_benchmark(int workers) {
    int threads = workers > 0 ? workers : (int)std::thread::hardware_concurrency();
    if (threads <= 0) threads = 1;

    std::cout << "\n==========================================================\n"
              << "  RUNNING C++ BITCOIN PUZZLE SPEED BENCHMARK\n"
              << "  Hardware Threads : " << threads << "\n"
              << "  Benchmark Sample : 1,000,000 keys\n"
              << "==========================================================\n";

    RangeInfo rng;
    rng.puzzle = 71;
    rng.block = 0;
    rng.range_idx = 0;
    rng.start = parse_u128("2165506938261001469952");
    rng.end = rng.start + 1000000ULL;
    rng.range_size = 1000000ULL;
    rng.target_address = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"; // Dummy non-matching target
    rng.lower = rng.start;
    rng.total = 1000000ULL;

    scan_range(71, 0, 0, rng.start, rng.end, rng, "benchmark_runner", threads, "");

    std::cout << "[✓] Benchmark completed successfully.\n\n";
}

// ---------------------------------------------------------------------------
// Verify a single Private Key cryptographically and check against Puzzle target
// ---------------------------------------------------------------------------
int verify_single_key(const std::string& raw_key, const std::string& target_addr, bool json_format) {
    u128 key = 0;
    if (raw_key.rfind("0x", 0) == 0 || raw_key.rfind("0X", 0) == 0) {
        key = parse_u128_hex(raw_key.substr(2));
    } else {
        bool all_digits = true;
        for (char c : raw_key) {
            if (!isdigit(c)) { all_digits = false; break; }
        }
        if (all_digits) key = parse_u128(raw_key);
        else key = parse_u128_hex(raw_key);
    }

    if (key == 0) {
        if (json_format) std::cout << "{\"error\":\"Invalid private key or key is 0\"}\n";
        else std::cerr << "[!] Error: Invalid private key or key is 0\n";
        return 1;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    uint8_t priv_bytes[32] = {0};
    for (int i = 0; i < 16; ++i) {
        priv_bytes[31 - i] = (uint8_t)(key >> (i * 8));
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_bytes)) {
        secp256k1_context_destroy(ctx);
        if (json_format) std::cout << "{\"error\":\"Failed to derive secp256k1 public key\"}\n";
        else std::cerr << "[!] Error: Failed to derive secp256k1 public key\n";
        return 1;
    }

    uint8_t serialized[33];
    size_t ser_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, serialized, &ser_len, &pubkey, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);

    uint8_t sha[32];
    uint8_t h160[20];
    SHA256(serialized, 33, sha);
    RIPEMD160(sha, 32, h160);

    std::string derived_addr = b58check_encode(0x00, h160);

    char pub_hex[67];
    for (int i = 0; i < 33; ++i) snprintf(pub_hex + i * 2, 3, "%02x", serialized[i]);
    char h160_hex[41];
    for (int i = 0; i < 20; ++i) snprintf(h160_hex + i * 2, 3, "%02x", h160[i]);

    int bits = 0;
    u128 tmp = key;
    while (tmp > 0) { bits++; tmp >>= 1; }

    u128 p71_lower = ((u128)1) << 70;
    u128 p71_upper = (((u128)1) << 71) - 1;
    bool in_range = (key >= p71_lower && key <= p71_upper);
    bool is_match = (derived_addr == target_addr);

    if (json_format) {
        std::cout << "{\n"
                  << "  \"keyDec\": \"" << u128_to_dec(key) << "\",\n"
                  << "  \"keyHex\": \"" << u128_to_hex64(key) << "\",\n"
                  << "  \"pubkey\": \"" << pub_hex << "\",\n"
                  << "  \"hash160\": \"" << h160_hex << "\",\n"
                  << "  \"address\": \"" << derived_addr << "\",\n"
                  << "  \"targetAddress\": \"" << target_addr << "\",\n"
                  << "  \"isTargetMatch\": " << (is_match ? "true" : "false") << ",\n"
                  << "  \"bitLength\": " << bits << ",\n"
                  << "  \"isInPuzzle71Range\": " << (in_range ? "true" : "false") << "\n"
                  << "}\n";
    } else {
        std::cout << "==========================================================\n"
                  << "  SECP256K1 KEY & BITCOIN ADDRESS VERIFICATION\n"
                  << "==========================================================\n"
                  << "  Private Key (Dec) : " << u128_to_dec(key) << "\n"
                  << "  Private Key (Hex) : 0x" << u128_to_hex64(key) << "\n"
                  << "  Bit Length        : " << bits << " bits\n"
                  << "  Compressed Pubkey : " << pub_hex << " (33 bytes)\n"
                  << "  Hash160 (RIPEMD)  : " << h160_hex << "\n"
                  << "  Derived Address   : " << derived_addr << "\n"
                  << "  Target Address    : " << target_addr << "\n"
                  << "  Matches Target?   : " << (is_match ? ">>> YES! MATCH FOUND! <<<" : "NO (Different address)") << "\n"
                  << "  In Puzzle 71?     : " << (in_range ? "YES (Within 2^70..2^71-1)" : "NO") << "\n"
                  << "==========================================================\n";
    }
    return is_match ? 0 : 2;
}

// ---------------------------------------------------------------------------
// Help Menu
// ---------------------------------------------------------------------------
void print_help(const char* prog) {
    std::cout << "Usage: " << prog << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  --puzzle <id>      Puzzle number (default: 71)\n"
              << "  --user <name>      Worker username for pool credits (default: lucky)\n"
              << "  --workers <N|max>  Thread count (default: all CPU cores)\n"
              << "  --api-base <url>   Server URL (default: http://65.20.91.208/puzzle_server.php)\n"
              << "  --once             Fetch and solve exactly 1 pool range, submit result, and exit\n"
              << "  --count <N>        Fetch and solve N pool ranges, submit results, and exit\n"
              << "  --benchmark        Run local performance benchmark and exit\n"
              << "  --verify <key>     Cryptographically derive address for a private key and exit\n"
              << "  --verify-json <k>  Derive address and print structured JSON output\n"
              << "  --analyze          Fetch target range and display keyspace statistics\n"
              << "  --range <S> <E>    Scan a manual offline range [Start, End)\n"
              << "  --target <addr>    Target Bitcoin address for manual range\n"
              << "  --help, -h         Show this help message\n\n"
              << "Example:\n"
              << "  " << prog << " --puzzle 71 --user lucky --once\n"
              << "  " << prog << " --puzzle 71 --user lucky --workers max\n"
              << "  " << prog << " --verify 1 --target 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH\n"
              << "  " << prog << " --benchmark\n";
}

// ---------------------------------------------------------------------------
// Main Entry Point
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    curl_global_init(CURL_GLOBAL_ALL);

    int puzzle_id = 71;
    std::string user = "lucky";
    int workers = (int)std::thread::hardware_concurrency();
    if (workers <= 0) workers = 1;
    std::string api_base = "http://65.20.91.208/puzzle_server.php";
    bool do_benchmark = false;
    bool do_analyze = false;
    int max_ranges = -1;
    std::string manual_start = "";
    std::string manual_end = "";
    std::string manual_target = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU";

    std::string verify_key_input = "";
    bool verify_json = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--puzzle" && i + 1 < argc) {
            puzzle_id = std::stoi(argv[++i]);
        } else if (arg == "--user" && i + 1 < argc) {
            user = argv[++i];
        } else if (arg == "--workers" && i + 1 < argc) {
            std::string w = argv[++i];
            if (w == "max") {
                workers = (int)std::thread::hardware_concurrency();
            } else {
                workers = std::max(1, std::stoi(w));
            }
        } else if (arg == "--api-base" && i + 1 < argc) {
            api_base = argv[++i];
        } else if (arg == "--once") {
            max_ranges = 1;
        } else if (arg == "--count" && i + 1 < argc) {
            max_ranges = std::max(1, std::stoi(argv[++i]));
        } else if (arg == "--benchmark") {
            do_benchmark = true;
        } else if (arg == "--verify" && i + 1 < argc) {
            verify_key_input = argv[++i];
            verify_json = false;
        } else if (arg == "--verify-json" && i + 1 < argc) {
            verify_key_input = argv[++i];
            verify_json = true;
        } else if (arg == "--analyze") {
            do_analyze = true;
        } else if (arg == "--range" && i + 2 < argc) {
            manual_start = argv[++i];
            manual_end = argv[++i];
        } else if (arg == "--target" && i + 1 < argc) {
            manual_target = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            print_help(argv[0]);
            curl_global_cleanup();
            return 0;
        }
    }

    if (!verify_key_input.empty()) {
        int rc = verify_single_key(verify_key_input, manual_target, verify_json);
        curl_global_cleanup();
        return rc;
    }

    std::cout << "==========================================================\n"
              << "  BITCOIN PUZZLE " << puzzle_id << " - HIGH-SPEED C/C++ CLIENT\n"
              << "  User      : " << user << "\n"
              << "  Workers   : " << workers << " CPU threads\n"
              << (max_ranges > 0 ? ("  Target Run: " + std::to_string(max_ranges) + " real pool range(s)\n") : "  Mode      : Continuous Pool Worker\n")
              << "==========================================================\n\n";

    if (do_benchmark) {
        run_benchmark(workers);
        curl_global_cleanup();
        return 0;
    }

    if (!manual_start.empty() && !manual_end.empty()) {
        std::cout << "[*] Running in standalone local range mode...\n";
        RangeInfo rng;
        rng.puzzle = puzzle_id;
        rng.block = 0;
        rng.range_idx = 0;
        rng.start = parse_u128(manual_start);
        rng.end = parse_u128(manual_end);
        rng.range_size = (uint64_t)(rng.end - rng.start);
        rng.target_address = manual_target;
        rng.lower = rng.start;
        rng.total = rng.range_size;
        scan_range(puzzle_id, 0, 0, rng.start, rng.end, rng, user, workers, "");
        curl_global_cleanup();
        return 0;
    }

    // Pool mode
    int ranges_processed = 0;
    while (g_running.load() && (max_ranges < 0 || ranges_processed < max_ranges)) {
        std::string url = api_base + "?action=range&puzzle=" + std::to_string(puzzle_id) + "&user=" + user;
        std::string resp = http_get(url);

        RangeInfo rng;
        if (!parse_range_json(resp, rng)) {
            std::cout << "[!] No work available or server timeout. Retrying in 10s...\n";
            for (int s = 0; s < 10 && g_running.load(); ++s) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            continue;
        }

        if (do_analyze) {
            run_analysis(rng);
            break;
        }

        std::cout << "[*] Assigned block " << rng.block << ", range " << rng.range_idx
                  << " (" << format_commas(rng.range_size) << " keys) Target: " << rng.target_address << "\n";

        ranges_processed++;
        bool found = scan_range(
            puzzle_id,
            rng.block,
            rng.range_idx,
            rng.start,
            rng.end,
            rng,
            user,
            workers,
            api_base
        );

        if (found) {
            std::cout << "[+] Exiting work loop: TARGET KEY FOUND!\n";
            break;
        }
    }

    std::cout << "[*] Worker stopped. Total ranges processed: " << ranges_processed << "\n";
    curl_global_cleanup();
    return 0;
}
