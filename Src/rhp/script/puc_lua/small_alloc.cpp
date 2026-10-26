#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <new>

#include <rhp/script/puc_lua/small_alloc.hpp>

namespace Rhp::script::detail {

namespace {
// Empty slabs the pool keeps besides a region it would give back: a script whose live objects hover
// around a region's worth doesn't get and give back a region over and over.
constexpr std::size_t kSpareSlabs = small_alloc::kRegionSlabs / 2;
} // namespace

small_alloc::~small_alloc() {
    while (regions_ != nullptr) {
        region* r = regions_;
        regions_ = r->next;
        void* base = reinterpret_cast<std::byte*>(r) - kSlabHeader;
        if (upstream_ != nullptr) {
            upstream_->deallocate(base, kRegionSize, kSlabSize);
        } else {
            ::operator delete(base, kRegionSize, std::align_val_t{kSlabSize});
        }
    }
}

void small_alloc::unlist(slab* s) noexcept {
    if (s->prev != nullptr) {
        s->prev->next = s->next;
    } else {
        partial_[s->cls] = s->next;
    }
    if (s->next != nullptr) {
        s->next->prev = s->prev;
    }
    s->prev = nullptr;
    s->next = nullptr;
    s->listed = false;
}

small_alloc::slab* small_alloc::take_slab() noexcept {
    if (slab* s = pool_) {
        pool_ = s->next;
        if (pool_ != nullptr) {
            pool_->prev = nullptr;
        }
        --pool_count_;
        ++s->owner->slabs_out;
        return s;
    }
    if (fresh_ == nullptr || fresh_->fresh == kRegionSlabs) {
        void* base = nullptr;
        if (upstream_ != nullptr) {
            try {
                base = upstream_->allocate(kRegionSize, kSlabSize);
            } catch (...) { // the resource is out of memory: so is Lua
                return nullptr;
            }
        } else {
            base = ::operator new(kRegionSize, std::align_val_t{kSlabSize}, std::nothrow);
        }
        if (base == nullptr) {
            return nullptr;
        }
        auto* r = reinterpret_cast<region*>(static_cast<std::byte*>(base) + kSlabHeader);
        r->prev = nullptr;
        r->next = regions_;
        if (regions_ != nullptr) {
            regions_->prev = r;
        }
        r->slabs_out = 0;
        r->fresh = 0;
        regions_ = r;
        fresh_ = r;
        ++regions_count_;
    }
    std::byte* base = reinterpret_cast<std::byte*>(fresh_) - kSlabHeader;
    auto* s = reinterpret_cast<slab*>(base + fresh_->fresh * kSlabSize);
    s->owner = fresh_;
    ++fresh_->fresh;
    ++fresh_->slabs_out;
    return s;
}

void* small_alloc::allocate_slow(std::uint8_t c) noexcept {
    slab* s = take_slab();
    if (s == nullptr) {
        return nullptr;
    }
    // Slab 0 of a region starts after the region's header too.
    std::byte* const start = reinterpret_cast<std::byte*>(s) + kSlabHeader;
    std::byte* const first = start == reinterpret_cast<std::byte*>(s->owner) ? start + kRegionHeader : start;
    const auto size = static_cast<std::uint32_t>(small_classes::kSizes[c]);
    const std::size_t blocks = (reinterpret_cast<std::byte*>(s) + kSlabSize - first) / size;
    s->free = nullptr;
    s->bump = first + size; // the first block is the one returned
    s->end = first + blocks * size;
    s->prev = nullptr;
    s->next = nullptr;
    s->used = 1;
    s->size = size;
    s->cls = c;
    s->listed = true;
    partial_[c] = s; // allocate_slow runs only when the class has no slab with room
    return first;
}

void small_alloc::freed_slow(slab* s) noexcept {
    if (s->used == 0) { // empty (a slab holds dozens of blocks: it was listed): back to the pool
        retire(s);
        return;
    }
    // It was full: it has room again.
    s->prev = nullptr;
    s->next = partial_[s->cls];
    if (s->next != nullptr) {
        s->next->prev = s;
    }
    partial_[s->cls] = s;
    s->listed = true;
}

void small_alloc::retire(slab* s) noexcept {
    unlist(s);
    s->next = pool_;
    if (pool_ != nullptr) {
        pool_->prev = s;
    }
    pool_ = s;
    ++pool_count_;
    region* r = s->owner;
    if (--r->slabs_out == 0 && pool_count_ - r->fresh >= kSpareSlabs) {
        release(r);
    }
}

// Every slab of `r` that was ever used is in the pool (none serves a class).
void small_alloc::release(region* r) noexcept {
    std::byte* const base = reinterpret_cast<std::byte*>(r) - kSlabHeader;
    for (std::uint32_t i = 0; i < r->fresh; ++i) {
        auto* s = reinterpret_cast<slab*>(base + i * kSlabSize);
        if (s->prev != nullptr) {
            s->prev->next = s->next;
        } else {
            pool_ = s->next;
        }
        if (s->next != nullptr) {
            s->next->prev = s->prev;
        }
    }
    pool_count_ -= r->fresh;
    if (r->prev != nullptr) {
        r->prev->next = r->next;
    } else {
        regions_ = r->next;
    }
    if (r->next != nullptr) {
        r->next->prev = r->prev;
    }
    if (fresh_ == r) {
        fresh_ = nullptr;
    }
    --regions_count_;
    if (upstream_ != nullptr) {
        upstream_->deallocate(base, kRegionSize, kSlabSize);
    } else {
        ::operator delete(base, kRegionSize, std::align_val_t{kSlabSize});
    }
}

} // namespace Rhp::script::detail
