#pragma once

// RHP — Remote Hot Patch. One include for everything the library offers.
// Modules arrive stage by stage; this header grows with them.

#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/errors_mode.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/script/marshal.hpp>
#include <rhp/script/patch_point.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/stack.hpp>
#include <rhp/script/stubs.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/utils/crc32c.hpp>
#include <rhp/utils/fixed_string.hpp>
#include <rhp/utils/function_traits.hpp>
#include <rhp/utils/overloaded.hpp>
#include <rhp/utils/scope_guard.hpp>
#include <rhp/utils/spsc_ring.hpp>
#include <rhp/utils/type_list.hpp>
#include <rhp/utils/units.hpp>
