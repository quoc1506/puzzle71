/**
 * Secp256k1 Distributed Worker (C++)
 *
 * Build:
 * c++ -O3 -std=c++17 -pthread -I/usr/local/opt/secp256k1/include -o worker worker.cpp -L/usr/local/opt/secp256k1/lib -lsecp256k1 -lcurl -lssl -lcrypto -lpthread
 *
 * Ubuntu/Debian Build:
 * g++ -O3 -march=native -std=c++17 -pthread -o worker worker.cpp -lsecp256k1 -lcurl -lssl -lcrypto
 *
 * Usage:
 * ./worker --user worker-01 --puzzle 71 --workers max --api-base http://findbtc.test/server/puzzle_server.php
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
#include <cstdlib>

#include <curl/curl.h>
#include <secp256k1.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static std::atomic<bool> g_running(true);

void sigint_handler(int signum) {
    (void)signum;
    g_running = false;
    std::cout << "\n[INFO] Stopping worker cleanly...\n";
}

typedef __uint128_t u128;

u128 parse_u128(const std::string& str) {
    u128 res = 0;
    for (char c : str) {
        if (c >= '0' && c <= '9') res = res * 10 + (c - '0');
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

std::string format_commas(uint64_t n) {
    std::string s = std::to_string(n);
    int insertPosition = (int)s.length() - 3;
    while (insertPosition > 0) {
        s.insert(insertPosition, ",");
        insertPosition -= 3;
    }
    return s;
}

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

    uint8_t sha1[32], sha2[32];
    SHA256(bytes.data(), 21, sha1);
    SHA256(sha1, 32, sha2);
    if (memcmp(sha2, bytes.data() + 21, 4) != 0) return false;

    memcpy(hash160_out, bytes.data() + 1, 20);
    return true;
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string http_get(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";
    std::string readBuffer;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "sys-monitor/1.0");
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return (res == CURLE_OK) ? readBuffer : "";
}

bool http_post(const std::string& url, const std::string& json_data, std::string* response_out = nullptr) {
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
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (res == CURLE_OK && response_out) *response_out = responseBuffer;
    return (res == CURLE_OK);
}

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
        while (end < json.length() && json[end] != ',' && json[end] != '}' && json[end] != '\n') end++;
        return json.substr(pos, end - pos);
    }
}

struct RangeInfo {
    int puzzle;
    int64_t block;
    int range_idx;
    u128 start;
    u128 end;
    uint64_t range_size;
    std::string target_address;
    u128 lower;
    u128 total;
};

bool parse_range_json(const std::string& json, RangeInfo& rng) {
    if (json.empty() || json.find("\"start\"") == std::string::npos) return false;
    std::string s_p = json_get_string(json, "puzzle");
    rng.puzzle = s_p.empty() ? 71 : std::stoi(s_p);
    std::string s_b = json_get_string(json, "block");
    rng.block = s_b.empty() ? 0 : std::stoll(s_b);
    std::string s_r = json_get_string(json, "range_idx");
    rng.range_idx = s_r.empty() ? 0 : std::stoi(s_r);
    rng.start = parse_u128(json_get_string(json, "start"));
    rng.end = parse_u128(json_get_string(json, "end"));
    std::string s_sz = json_get_string(json, "range_size");
    rng.range_size = s_sz.empty() ? 0 : std::stoull(s_sz);
    rng.target_address = json_get_string(json, "target_address");
    rng.lower = parse_u128(json_get_string(json, "lower"));
    rng.total = parse_u128(json_get_string(json, "total"));
    return (!rng.target_address.empty() && rng.end > rng.start);
}

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

    uint8_t priv_one[32] = {0};
    priv_one[31] = 1;
    secp256k1_pubkey G_pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &G_pubkey, priv_one)) {
        secp256k1_context_destroy(ctx);
        return;
    }

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
        ser_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, serialized, &ser_len, &cur_pubkey, SECP256K1_EC_COMPRESSED);

        SHA256(serialized, 33, sha);
        RIPEMD160(sha, 32, h160);

        if (*(const uint64_t*)h160 == target_h64_first) {
            if (memcmp(h160 + 8, target_hash160 + 8, 12) == 0) {
                std::lock_guard<std::mutex> lk(found_mtx);
                found_key = cur_key;
                found_flag.store(true, std::memory_order_release);
                break;
            }
        }

        if (secp256k1_ec_pubkey_combine(ctx, &next_pubkey, add_inputs, 2)) {
            cur_pubkey = next_pubkey;
        } else {
            cur_key++;
            local_counter++;
            u128 next_val = cur_key;
            for (int i = 0; i < 16; ++i) priv_start[31 - i] = (uint8_t)(next_val >> (i * 8));
            (void)secp256k1_ec_pubkey_create(ctx, &cur_pubkey, priv_start);
            continue;
        }

        cur_key++;
        local_counter++;

        if ((local_counter & 0x1FFF) == 0) {
            checked_counter.fetch_add(8192, std::memory_order_relaxed);
        }
    }

    uint64_t rem = local_counter & 0x1FFF;
    if (rem > 0) checked_counter.fetch_add(rem, std::memory_order_relaxed);
    secp256k1_context_destroy(ctx);
}

void print_help(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n\n"
              << "Options:\n"
              << "  --user <name>            Worker identifier (default: worker-01)\n"
              << "  --puzzle <id>            Puzzle ID to scan (e.g. 71, default: auto from server)\n"
              << "  --workers <count>        Number of worker threads (default: hardware concurrency)\n"
              << "  --api-base <url>         Puzzle server API endpoint\n"
              << "  --help, -h               Show this help message\n";
}

int main(int argc, char* argv[]) {
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    curl_global_init(CURL_GLOBAL_ALL);

    int puzzle_id = 0;
    std::string user = "worker-01";
    int threads = (int)std::thread::hardware_concurrency();
    if (threads <= 0) threads = 4;
    std::string api_base = "http://findbtc.test/server/puzzle_server.php";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_help(argv[0]);
            return 0;
        } else if (arg == "--user" && i + 1 < argc) {
            user = argv[++i];
        } else if (arg == "--puzzle" && i + 1 < argc) {
            puzzle_id = std::stoi(argv[++i]);
        } else if (arg == "--workers" && i + 1 < argc) {
            std::string val = argv[++i];
            if (val == "max" || val == "MAX") {
                threads = (int)std::thread::hardware_concurrency();
                if (threads <= 0) threads = 4;
            } else {
                threads = std::max(1, std::stoi(val));
            }
        } else if (arg == "--workers=max" || arg == "worker=max" || arg == "--worker=max") {
            threads = (int)std::thread::hardware_concurrency();
            if (threads <= 0) threads = 4;
        } else if (arg == "--api-base" && i + 1 < argc) {
            api_base = argv[++i];
        }
    }

    std::cout << "========================================================\n";
    std::cout << "  Secp256k1 Distributed Worker Engine                  \n";
    std::cout << "========================================================\n";
    std::cout << "  User / Node ID   : " << user << "\n";
    std::cout << "  Active Workers   : " << threads << " thread(s)\n";
    std::cout << "  Target Puzzle    : " << (puzzle_id > 0 ? std::to_string(puzzle_id) : "Auto (from server)") << "\n";
    std::cout << "  Server API Base  : " << api_base << "\n";
    std::cout << "========================================================\n\n";

    while (g_running.load()) {
        std::string url = api_base + "?action=range&user=" + user;
        if (puzzle_id > 0) {
            url += "&puzzle=" + std::to_string(puzzle_id);
        }
        std::string resp = http_get(url);

        RangeInfo rng;
        if (!parse_range_json(resp, rng)) {
            std::cout << "[WAIT] Server returned no range or idle response. Retrying in 5 seconds...\n";
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        uint8_t target_h160[20];
        if (!b58check_decode_hash160(rng.target_address, target_h160)) {
            std::cerr << "[ERROR] Invalid target address format: " << rng.target_address << "\n";
            std::this_thread::sleep_for(std::chrono::seconds(3));
            continue;
        }
        uint64_t target_h64 = *(const uint64_t*)target_h160;

        u128 total_keys = rng.end - rng.start;
        u128 chunk_size = (total_keys + threads - 1) / threads;

        std::atomic<bool> found_flag(false);
        u128 found_key = 0;
        std::mutex found_mtx;
        std::atomic<uint64_t> checked_counter(0);

        std::vector<std::thread> pool;
        auto t_start = std::chrono::high_resolution_clock::now();

        std::cout << "[WORK] Block " << rng.block << " | Range #" << rng.range_idx
                  << " | Size: " << format_commas(rng.range_size)
                  << " keys | Distributing to " << threads << " threads...\n";

        for (int i = 0; i < threads; ++i) {
            u128 cs = rng.start + i * chunk_size;
            u128 ce = std::min(rng.start + (i + 1) * chunk_size, rng.end);
            if (cs < ce) {
                pool.emplace_back(scan_worker, cs, ce, target_h160, target_h64,
                                  std::ref(found_flag), std::ref(found_key),
                                  std::ref(found_mtx), std::ref(checked_counter));
            }
        }

        for (auto& th : pool) if (th.joinable()) th.join();

        auto t_end = std::chrono::high_resolution_clock::now();
        double elapsed = std::chrono::duration<double>(t_end - t_start).count();
        if (elapsed <= 0.0) elapsed = 0.001;

        uint64_t checked = checked_counter.load();
        double speed = (double)checked / elapsed;
        bool hit = found_flag.load();

        std::cout << "       Result: " << (hit ? "Found" : "Done")
                  << " | Rate: " << format_commas((uint64_t)speed) << " keys/sec"
                  << " | Time: " << std::fixed << std::setprecision(2) << elapsed << "s\n";

        std::stringstream json;
        json << "{\"action\":\"result\",\"puzzle\":" << rng.puzzle << ",\"block\":" << rng.block
             << ",\"range_idx\":" << rng.range_idx
             << ",\"status\":\"" << (hit ? "found" : "done") << "\""
             << ",\"private_key\":\"" << (hit ? u128_to_hex64(found_key) : "") << "\""
             << ",\"user\":\"" << user << "\""
             << ",\"speed\":" << std::fixed << std::setprecision(1) << speed
             << ",\"elapsed\":" << std::fixed << std::setprecision(2) << elapsed << "}";

        std::string ack;
        http_post(api_base, json.str(), &ack);

        if (hit) {
            found_key = 0;
            break;
        }
    }

    curl_global_cleanup();
    std::cout << "[INFO] Worker exited successfully.\n";
    return 0;
}