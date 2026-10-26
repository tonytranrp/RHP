// The journal of script writes to host memory through views (typed views and struct views).
//
// One layer per (target memory, code that wrote it): the first write of a module's request (or
// handler call) to a span or an object makes a layer, an effect in that sandbox's ledger; every
// write keeps the original of the elements (or bytes, for objects) it changes, copied the first time
// that layer writes them. Undoing the layer puts those originals back.
//
// Layers of the same target (the same binding called with the same arguments) stack process-wide,
// like var_layers: undoing a layer hands each original to the next newer layer that also wrote that
// element instead of restoring it, so the memory always ends up as if the undone writes never
// happened, whatever order modules (or sandboxes) are reverted in. Undo finds the memory again
// through its own copy of the view's source: memory that moved (a vector that grew) is restored where
// it is now; memory that is gone (a dead handle, a null pointer) has nothing to restore.

#include <algorithm>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <rhp/script/detail/context.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/puc_lua/views_impl.hpp>
#include <rhp/script/views.hpp>

namespace Rhp::script::detail {

namespace {

class region_layer;

struct layer_group {
    std::vector<region_layer*> layers; // oldest first
};

struct journal_registry {
    std::mutex mutex;
    std::vector<std::unique_ptr<layer_group>> groups;
};

journal_registry& registry() {
    static journal_registry r;
    return r;
}

// Bumped whenever a layer goes away: a node's cached layer is valid while it is unchanged.
std::atomic<std::uint64_t>& epoch() {
    static std::atomic<std::uint64_t> e{1};
    return e;
}

// The originals are kept in pages of 4 KiB, made when a unit of the page is first written: a few
// writes into a large span (a texture) keep a few pages, not a copy of all of it.
constexpr std::size_t kPageShift = 12;
constexpr std::size_t kPageBytes = std::size_t{1} << kPageShift;

struct page {
    std::byte orig[kPageBytes];
    std::uint64_t mask[kPageBytes / 64]; // one bit per unit (at most one unit per byte)
};

class region_layer final : public effect {
public:
    // `unit`: 1, 2, 4 or 8 bytes.
    region_layer(std::unique_ptr<view_source> source, const context* ctx, effect_owner owner, std::size_t unit)
        : source_(std::move(source)), ctx_(ctx), owner_(owner), unit_shift_(static_cast<unsigned>(std::countr_zero(unit))) {}

    region_layer(const region_layer&) = delete;
    region_layer& operator=(const region_layer&) = delete;

    ~region_layer() override { detach(false); }

    void undo() override { detach(true); }

    [[nodiscard]] const view_source& source() const noexcept { return *source_; }
    [[nodiscard]] bool owned_by(const context* ctx, const effect_owner& owner) const noexcept { return ctx_ == ctx && owner_ == owner; }

    // Keeps the originals of the units in [offset, offset + len) of the root it doesn't hold yet.
    void keep(const std::byte* root, std::size_t offset, std::size_t len) {
        if (len == 0) {
            return;
        }
        const std::size_t last = (offset + len - 1) >> unit_shift_;
        for (std::size_t u = offset >> unit_shift_; u <= last; ++u) {
            page* p = page_of(u);
            if (p == nullptr) {
                const std::size_t index = u >> page_units_shift();
                if (index >= pages_.size()) {
                    pages_.resize(index + 1);
                }
                pages_[index] = std::make_unique<page>(); // zeroed mask
                p = pages_[index].get();
            }
            const std::size_t i = u & (page_units() - 1);
            std::uint64_t& word = p->mask[i / 64];
            const std::uint64_t bit = std::uint64_t{1} << (i % 64);
            if ((word & bit) == 0) {
                std::memcpy(p->orig + (i << unit_shift_), root + (u << unit_shift_), unit());
                word |= bit;
            }
        }
    }

    void attach(layer_group* group) noexcept { group_ = group; }

private:
    [[nodiscard]] std::size_t unit() const noexcept { return std::size_t{1} << unit_shift_; }
    [[nodiscard]] std::size_t page_units_shift() const noexcept { return kPageShift - unit_shift_; }
    [[nodiscard]] std::size_t page_units() const noexcept { return std::size_t{1} << page_units_shift(); }

    [[nodiscard]] page* page_of(std::size_t u) const noexcept {
        const std::size_t index = u >> page_units_shift();
        return index < pages_.size() ? pages_[index].get() : nullptr;
    }

    // The original of unit u (which this layer wrote).
    [[nodiscard]] std::byte* orig_of(std::size_t u) const noexcept { return page_of(u)->orig + ((u & (page_units() - 1)) << unit_shift_); }

    [[nodiscard]] bool has(std::size_t u) const noexcept {
        const page* p = page_of(u);
        const std::size_t i = u & (page_units() - 1);
        return p != nullptr && ((p->mask[i / 64] >> (i % 64)) & 1u) != 0;
    }

    // Calls fn(unit, mask word, bit) for every unit this layer wrote.
    template <class Fn>
    void each_written(Fn fn) {
        const std::size_t words = page_units() / 64 == 0 ? 1 : page_units() / 64;
        for (std::size_t index = 0; index < pages_.size(); ++index) {
            page* p = pages_[index].get();
            if (p == nullptr) {
                continue;
            }
            for (std::size_t w = 0; w < words; ++w) {
                for (std::uint64_t bits = p->mask[w]; bits != 0; bits &= bits - 1) {
                    const auto b = static_cast<std::size_t>(std::countr_zero(bits));
                    fn((index << page_units_shift()) + w * 64 + b, p->mask[w], std::uint64_t{1} << b);
                }
            }
        }
    }

    void detach(bool restore) noexcept {
        if (group_ == nullptr) {
            return;
        }
        journal_registry& reg = registry();
        const std::scoped_lock lock{reg.mutex};
        auto& layers = group_->layers;
        const auto me = std::ranges::find(layers, this);
        // Hand each original to the next newer layer that wrote the same unit: it restores it.
        bool left = false;
        each_written([&](std::size_t u, std::uint64_t& word, std::uint64_t bit) {
            for (auto newer = me == layers.end() ? me : std::next(me); newer != layers.end(); ++newer) {
                if ((*newer)->has(u)) {
                    std::memcpy((*newer)->orig_of(u), orig_of(u), unit());
                    word &= ~bit;
                    return;
                }
            }
            left = true;
        });
        if (restore && left) {
            // The memory where it is now; gone memory has nothing to restore.
            if (const result<region> now = source_->resolve()) {
                each_written([&](std::size_t u, std::uint64_t&, std::uint64_t) {
                    if (((u + 1) << unit_shift_) <= now->size) {
                        std::memcpy(now->data + (u << unit_shift_), orig_of(u), unit());
                    }
                });
            }
        }
        if (me != layers.end()) {
            layers.erase(me);
        }
        if (layers.empty()) {
            const layer_group* gone = group_;
            std::erase_if(reg.groups, [gone](const std::unique_ptr<layer_group>& g) { return g.get() == gone; });
        }
        group_ = nullptr;
        epoch().fetch_add(1, std::memory_order_acq_rel);
    }

    std::unique_ptr<view_source> source_;
    const context* ctx_;
    effect_owner owner_;
    unsigned unit_shift_;                      // log2 of the unit: an element of a span, a byte of an object
    std::vector<std::unique_ptr<page>> pages_; // the originals this layer wrote, by page
    layer_group* group_ = nullptr;             // null once detached
};

// The group of layers writing the same memory as `source` (registry lock held).
layer_group* group_of(journal_registry& reg, const view_source& source) noexcept {
    for (const auto& g : reg.groups) {
        if (!g->layers.empty() && g->layers.front()->source().same(source)) {
            return g.get();
        }
    }
    return nullptr;
}

// Journal unit of a root: an element of a span, a byte of an object.
std::size_t unit_of(const view_node& root) noexcept {
    return root.shape == node_shape::kSpan ? elem_size(root.elem) : 1;
}

} // namespace

bool journal_touch(context& ctx, journal_cache& cache, const place& p, std::size_t offset, std::size_t len) {
    const effect_owner owner = ctx.current_owner();
    auto* layer = static_cast<region_layer*>(cache.layer);
    if (layer == nullptr || cache.epoch != epoch().load(std::memory_order_acquire) || cache.ctx != &ctx || !(cache.owner == owner)) {
        layer = nullptr;
        const view_node& root = *p.root;
        journal_registry& reg = registry();
        {
            const std::scoped_lock lock{reg.mutex};
            if (layer_group* g = group_of(reg, *root.source)) {
                for (auto it = g->layers.rbegin(); it != g->layers.rend(); ++it) {
                    if ((*it)->owned_by(&ctx, owner)) {
                        layer = *it;
                        break;
                    }
                }
            }
        }
        if (layer == nullptr) {
            auto made = std::make_unique<region_layer>(root.source->clone(), &ctx, owner, unit_of(root));
            region_layer* raw = made.get();
            {
                const std::scoped_lock lock{reg.mutex};
                layer_group* g = group_of(reg, *root.source);
                if (g == nullptr) {
                    g = reg.groups.emplace_back(std::make_unique<layer_group>()).get();
                }
                g->layers.push_back(raw);
                raw->attach(g);
            }
            // Recorded in the running code's ledger; a sandbox that is closing undoes (and destroys)
            // what is recorded at once.
            if (ctx.record_effect(std::string{root.label}, std::move(made)) == 0) {
                cache = journal_cache{};
                return false;
            }
            layer = raw;
        }
        cache = journal_cache{layer, epoch().load(std::memory_order_acquire), &ctx, owner};
    }
    layer->keep(p.root_data, offset, len);
    return true;
}

std::size_t journal_layers() noexcept {
    journal_registry& reg = registry();
    const std::scoped_lock lock{reg.mutex};
    std::size_t n = 0;
    for (const auto& g : reg.groups) {
        n += g->layers.size();
    }
    return n;
}

} // namespace Rhp::script::detail
