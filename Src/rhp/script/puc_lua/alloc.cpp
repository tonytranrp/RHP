// The allocator Lua runs on (sandbox_impl::allocate): small blocks from small_alloc, larger ones
// from the C heap or sandbox_options::memory, the memory limit and the allocation counters.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory_resource>

#include <lua.h>

#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/puc_lua/small_alloc.hpp>
#include <rhp/script/testing.hpp>

namespace Rhp::script::detail {

namespace {

// The alloc_kind of a new block from the tag Lua passes as its old size (the object's basic type).
constexpr std::size_t alloc_kind_of(std::size_t tag) noexcept {
    switch (tag) {
    case LUA_TSTRING: return static_cast<std::size_t>(alloc_kind::kString);
    case LUA_TTABLE: return static_cast<std::size_t>(alloc_kind::kTable);
    case LUA_TFUNCTION: return static_cast<std::size_t>(alloc_kind::kFunction);
    case LUA_TUSERDATA: return static_cast<std::size_t>(alloc_kind::kUserdata);
    case LUA_TTHREAD: return static_cast<std::size_t>(alloc_kind::kThread);
    case LUA_NUMTYPES: return static_cast<std::size_t>(alloc_kind::kUpvalue);       // LUA_TUPVAL
    case LUA_NUMTYPES + 1: return static_cast<std::size_t>(alloc_kind::kPrototype); // LUA_TPROTO
    default: return static_cast<std::size_t>(alloc_kind::kOther);
    }
}

} // namespace

void sandbox_impl::free_block(void* block, std::size_t size) noexcept {
    if (small_alloc::fits(size)) {
        small_.deallocate(block);
    } else if (memory_ == nullptr) {
        std::free(block);
    } else {
        memory_->deallocate(block, size, small_alloc::kAlignment);
    }
}

void* sandbox_impl::heap_allocate(std::size_t size) noexcept {
    if (memory_ == nullptr) {
        return std::malloc(size);
    }
    try {
        return memory_->allocate(size, small_alloc::kAlignment);
    } catch (...) {
        return nullptr;
    }
}

void* sandbox_impl::allocate(void* ud, void* ptr, std::size_t old_size, std::size_t new_size) noexcept {
    auto& self = *static_cast<sandbox_impl*>(ud);
    const std::size_t old_tag = old_size;
    if (ptr == nullptr) {
        old_size = 0; // Lua passes the object type here for new blocks
    }
    if (new_size == 0) {
        if (ptr != nullptr) {
            self.free_block(ptr, old_size);
            self.memory_used_ -= old_size;
            ++self.frees_;
        }
        return nullptr;
    }
    const std::size_t kind = ptr == nullptr ? alloc_kind_of(old_tag) : kAllocKinds;
    if (new_size > old_size) {
        const std::uint64_t limit = self.options_.limits.memory;
        run_budget* const budget = self.budget_; // innermost run with its own budget
        if (budget != nullptr && budget->sticky == sticky_stop::kMemory) {
            return nullptr;
        }
        if (limit != 0 && self.memory_used_ - old_size + new_size > limit) {
            if (budget != nullptr && budget->sticky == sticky_stop::kNone) {
                budget->sticky = sticky_stop::kMemory;
            }
            return nullptr;
        }
    }
    // Where a block lives follows from its size alone (Lua passes it back on every call): up to
    // small_alloc::kMaxSize in the small-object slabs, larger ones on the C heap or memory_.
    void* block = nullptr;
    const bool was_small = ptr != nullptr && small_alloc::fits(old_size);
    if (small_alloc::fits(new_size)) {
        if (was_small && (new_size < old_size || small_alloc::same_class(old_size, new_size))) {
            // Stays where it is: the same class, or smaller (a slab block is freed by its address,
            // whatever size it is freed as, so shrinking in place never fails).
            if (!small_alloc::same_class(old_size, new_size)) {
                if (void* moved = self.small_.allocate(new_size)) { // a smaller class when there is room
                    std::memcpy(moved, ptr, new_size);
                    self.small_.deallocate(ptr);
                    ptr = moved;
                }
            }
            block = ptr;
        } else {
            block = self.small_.allocate(new_size);
            if (block == nullptr) {
                return nullptr; // `ptr` is untouched
            }
            if (ptr != nullptr) {
                std::memcpy(block, ptr, std::min(old_size, new_size));
                self.free_block(ptr, old_size);
            }
        }
    } else if (was_small) {
        block = self.heap_allocate(new_size);
        if (block == nullptr) {
            return nullptr;
        }
        std::memcpy(block, ptr, old_size);
        self.small_.deallocate(ptr);
    } else if (self.memory_ == nullptr) {
        // The C heap, like Lua's own allocator: a block grows or shrinks in place when it can.
        block = std::realloc(ptr, new_size);
        if (block == nullptr) {
            return nullptr; // `ptr` is untouched
        }
    } else {
        block = self.heap_allocate(new_size);
        if (block == nullptr) {
            return nullptr;
        }
        if (ptr != nullptr) {
            std::memcpy(block, ptr, std::min(old_size, new_size));
            self.memory_->deallocate(ptr, old_size, small_alloc::kAlignment);
        }
    }
    self.memory_used_ = self.memory_used_ - old_size + new_size;
    if (new_size > old_size) {
        self.bytes_allocated_ += new_size - old_size;
        self.peak_ = std::max(self.peak_, self.memory_used_);
    }
    if (kind != kAllocKinds) {
        ++self.allocations_;
        ++self.objects_[kind];
    }
    return block;
}

} // namespace Rhp::script::detail
