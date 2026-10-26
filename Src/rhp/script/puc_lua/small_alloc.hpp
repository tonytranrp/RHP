#pragma once

// Private to Src/rhp/script/puc_lua: the sandbox's small-object allocator. Lua's small blocks
// (tables, closures, upvalues, short strings, ...) come from per-size-class slabs carved out of
// larger regions, so most allocations and frees are a pointer pop or push.
//
// Layout: a region is kRegionSize bytes aligned to kSlabSize, cut into kRegionSlabs slabs. A slab
// serves one size class; its header (at the slab's start, so a block finds it by masking its
// address) keeps the slab's free list, the never-used rest (`bump`) and how many blocks are out.
// Slab 0 of a region also holds the region's header. A slab with room is listed in its class
// (`partial_`); a full one is not. A slab that empties goes back to the allocator's pool of empty
// slabs (the next slab any class needs comes from there first), and a region whose slabs are all
// empty is given back when the pool keeps enough others.
//
// Regions come from the sandbox's std::pmr resource, or from the aligned global operator new. Under
// AddressSanitizer there is no pooling (fits() is false): every block is a heap block of its own, so
// a use after free in a Lua object is still caught.

#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <span>

#if defined(__SANITIZE_ADDRESS__)
#define RHP_SMALL_ALLOC_POOLS 0
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(hwaddress_sanitizer) || __has_feature(memory_sanitizer)
#define RHP_SMALL_ALLOC_POOLS 0
#endif
#endif
#ifndef RHP_SMALL_ALLOC_POOLS
#define RHP_SMALL_ALLOC_POOLS 1
#endif

namespace Rhp::script::detail {

namespace small_classes {

inline constexpr std::size_t kAlignment = alignof(std::max_align_t);
inline constexpr std::size_t kMaxSize = 128;

// The block sizes, smallest first: multiples of kAlignment, the last one kMaxSize. Measured (Lua
// 5.5, x64): a table is 48 bytes, a closure with one upvalue 40, an upvalue 40, a short string
// 24 + its length + 1, a small table's array or node part 13-48; 16-64 bytes are nearly every
// allocation of table, closure and string heavy code, and 65-128 bytes are mostly prototypes and
// bigger closures. Every 8 bytes up to 64 where blocks need 8-byte alignment (MSVC, 32-bit ABIs),
// every 16 where they need 16 (x86-64 System V, AArch64).
inline constexpr std::size_t kFine[] = {16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128};
inline constexpr std::size_t kCoarse[] = {16, 32, 48, 64, 80, 96, 112, 128};
inline constexpr std::span<const std::size_t> kSizes = kAlignment <= 8 ? std::span<const std::size_t>{kFine} : std::span<const std::size_t>{kCoarse};
inline constexpr std::size_t kCount = kSizes.size();

// kOf.of[(size + kAlignment - 1) / kAlignment]: the class of a block of `size` bytes.
struct table {
    std::uint8_t of[kMaxSize / kAlignment + 1];
};
consteval table make_table() {
    table t{};
    std::size_t c = 0;
    for (std::size_t slot = 0; slot <= kMaxSize / kAlignment; ++slot) {
        while (kSizes[c] < slot * kAlignment) {
            ++c;
        }
        t.of[slot] = static_cast<std::uint8_t>(c);
    }
    return t;
}
inline constexpr table kOf = make_table();

consteval bool valid() {
    for (std::size_t i = 0; i < kCount; ++i) {
        if (kSizes[i] % kAlignment != 0 || (i > 0 && kSizes[i] <= kSizes[i - 1])) {
            return false;
        }
    }
    return kSizes[kCount - 1] == kMaxSize;
}
static_assert(valid(), "size classes: increasing multiples of the alignment, up to kMaxSize");

} // namespace small_classes

class small_alloc {
public:
    // Every block is aligned like the sandbox's other blocks (alignof(std::max_align_t)).
    static constexpr std::size_t kAlignment = small_classes::kAlignment;
    static constexpr std::size_t kSlabSize = 4096;
    static constexpr std::size_t kRegionSlabs = 16;
    static constexpr std::size_t kRegionSize = kSlabSize * kRegionSlabs;
    static constexpr std::size_t kMaxSize = small_classes::kMaxSize; // larger blocks are the caller's
    static constexpr bool kPools = RHP_SMALL_ALLOC_POOLS != 0;
    static constexpr std::size_t slot(std::size_t size) noexcept { return (size + kAlignment - 1) / kAlignment; }

    // `upstream`: where regions come from; nullptr: the aligned global operator new.
    explicit small_alloc(std::pmr::memory_resource* upstream) noexcept : upstream_(upstream) {}
    ~small_alloc(); // gives back every region, whatever is still allocated in it

    small_alloc(const small_alloc&) = delete;
    small_alloc& operator=(const small_alloc&) = delete;

    // Whether a block of `size` bytes (> 0) comes from here.
    [[nodiscard]] static constexpr bool fits(std::size_t size) noexcept { return kPools && size <= kMaxSize; }
    // Whether a block of `from` bytes can stay where it is as `to` bytes (both fit()).
    [[nodiscard]] static constexpr bool same_class(std::size_t from, std::size_t to) noexcept { return small_classes::kOf.of[slot(from)] == small_classes::kOf.of[slot(to)]; }

    // A block of `size` bytes (0 < size <= kMaxSize); nullptr when no region can be had.
    [[nodiscard]] void* allocate(std::size_t size) noexcept {
        const std::uint8_t c = small_classes::kOf.of[slot(size)];
        slab* s = partial_[c];
        if (s == nullptr) [[unlikely]] {
            return allocate_slow(c);
        }
        void* block;
        if (free_block* b = s->free) {
            s->free = b->next;
            block = b;
        } else {
            block = s->bump;
            s->bump += s->size;
        }
        ++s->used;
        if (s->free == nullptr && s->bump == s->end) [[unlikely]] {
            unlist(s); // full
        }
        return block;
    }

    // Gives back a block allocate() returned (its size is the slab's business).
    void deallocate(void* block) noexcept {
        slab* s = slab_of(block);
        auto* b = static_cast<free_block*>(block);
        b->next = s->free;
        s->free = b;
        if (--s->used == 0 || !s->listed) [[unlikely]] {
            freed_slow(s);
        }
    }

    // Regions held right now (tests).
    [[nodiscard]] std::size_t regions() const noexcept { return regions_count_; }

    static constexpr std::size_t kClasses = small_classes::kCount;

private:
    struct free_block {
        free_block* next;
    };
    struct region;
    struct slab {
        free_block* free; // blocks given back
        std::byte* bump;  // the next never-used block
        std::byte* end;   // past the last whole block
        slab* prev;       // in its class's list (listed) or in the pool of empty slabs
        slab* next;
        region* owner;
        std::uint32_t used; // blocks out
        std::uint32_t size; // block size
        std::uint8_t cls;
        bool listed; // in partial_[cls]
    };
    struct region {
        region* prev;
        region* next;
        std::uint32_t slabs_out; // slabs serving a class
        std::uint32_t fresh;     // slabs [fresh, kRegionSlabs) never used yet
    };

    static constexpr std::size_t kSlabHeader = (sizeof(slab) + kAlignment - 1) / kAlignment * kAlignment;
    static constexpr std::size_t kRegionHeader = (sizeof(region) + kAlignment - 1) / kAlignment * kAlignment;

    static slab* slab_of(void* block) noexcept {
        return reinterpret_cast<slab*>(reinterpret_cast<std::uintptr_t>(block) & ~static_cast<std::uintptr_t>(kSlabSize - 1));
    }

    void* allocate_slow(std::uint8_t c) noexcept;
    void freed_slow(slab* s) noexcept;
    void unlist(slab* s) noexcept;
    [[nodiscard]] slab* take_slab() noexcept;
    void retire(slab* s) noexcept;
    void release(region* r) noexcept;

    std::pmr::memory_resource* upstream_;
    slab* partial_[kClasses]{}; // slabs with room, by class
    slab* pool_ = nullptr;      // empty slabs
    std::size_t pool_count_ = 0;
    region* regions_ = nullptr; // every region (the newest first)
    region* fresh_ = nullptr;   // the region whose never-used slabs come next
    std::size_t regions_count_ = 0;
};

} // namespace Rhp::script::detail
