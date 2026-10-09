// The driver ctest runs when the targets aren't built for libFuzzer: every seed, every file named on
// the command line, then `--iterations` deterministic mutations (byte flips, inserts, deletes,
// duplicated ranges, splices, boundary bytes). `--write-corpus <dir>` writes the seeds out as files
// (the starting corpus for a libFuzzer run).
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "fuzz_support.hpp"

namespace {

void run(const std::string& input) {
    (void)LLVMFuzzerTestOneInput(reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
}

std::string mutate(std::string s, const std::vector<std::string>& seeds, std::mt19937& rng) {
    constexpr std::size_t kMaxSize = 64u * 1024u;
    const char interesting[] = {'\0', '\x01', '\x7f', '\x80', '\xff', '\xc0', '\xc1', '\xdc', '\xde', '\xdf', '\x16'};
    const int edits = 1 + static_cast<int>(rng() % 8);
    for (int e = 0; e < edits; ++e) {
        const std::size_t at = s.empty() ? 0 : rng() % s.size();
        switch (rng() % 7) {
        case 0:
            if (!s.empty()) {
                s[at] = static_cast<char>(s[at] ^ static_cast<char>(1u << (rng() % 8)));
            }
            break;
        case 1: s.insert(s.begin() + static_cast<std::ptrdiff_t>(at), static_cast<char>(rng())); break;
        case 2:
            if (!s.empty()) {
                s.erase(at, 1 + rng() % std::min<std::size_t>(16, s.size() - at));
            }
            break;
        case 3:
            if (!s.empty() && s.size() < kMaxSize / 2) {
                const std::size_t n = 1 + rng() % std::min<std::size_t>(64, s.size() - at);
                s.insert(at, s.substr(at, n));
            }
            break;
        case 4: {
            const std::string& other = seeds[rng() % seeds.size()];
            if (!other.empty()) {
                const std::size_t from = rng() % other.size();
                s.insert(at, other.substr(from, 1 + rng() % (other.size() - from)));
            }
            break;
        }
        case 5:
            if (!s.empty()) {
                s[at] = interesting[rng() % sizeof(interesting)];
            }
            break;
        default:
            if (!s.empty()) {
                s.resize(at);
            }
            break;
        }
    }
    if (s.size() > kMaxSize) {
        s.resize(kMaxSize);
    }
    return s;
}

} // namespace

int main(int argc, char** argv) {
    long iterations = 3000;
    std::vector<std::string> files;
    std::string corpus_dir;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--iterations" && i + 1 < argc) {
            iterations = std::stol(argv[++i]);
        } else if (arg == "--write-corpus" && i + 1 < argc) {
            corpus_dir = argv[++i];
        } else {
            files.emplace_back(arg);
        }
    }
    const std::vector<std::string> seeds = rhp_fuzz_seeds();
    if (!corpus_dir.empty()) {
        std::filesystem::create_directories(corpus_dir);
        for (std::size_t i = 0; i < seeds.size(); ++i) {
            std::ofstream{std::filesystem::path{corpus_dir} / ("seed" + std::to_string(i)), std::ios::binary} << seeds[i];
        }
        std::printf("wrote %zu seeds to %s\n", seeds.size(), corpus_dir.c_str());
        return 0;
    }
    long ran = 0;
    for (const std::string& seed : seeds) {
        run(seed);
        ++ran;
    }
    for (const std::string& path : files) {
        std::ifstream in{path, std::ios::binary};
        run(std::string{std::istreambuf_iterator<char>{in}, {}});
        ++ran;
    }
    std::mt19937 rng{0x5eed};
    for (long i = 0; i < iterations && !seeds.empty(); ++i) {
        run(mutate(seeds[rng() % seeds.size()], seeds, rng));
        ++ran;
    }
    std::printf("ran %ld inputs\n", ran);
    return 0;
}
