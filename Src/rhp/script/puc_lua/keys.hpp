#pragma once

// Private to Src/rhp/script/puc_lua: the names RHP gives its metatables, registry entries and
// metatable fields, each spelled once. Scripts can't reach any of them (metatables are locked, the
// registry is out of reach), so they only need to differ from each other.

namespace Rhp::script::detail {

// Registry entries (luaL_newmetatable names included).
inline constexpr const char* kModuleProxyKey = "rhp.module";             // metatable of require() proxies (sandbox.cpp; the test bridge tells them apart)
inline constexpr const char* kModuleProxiesKey = "rhp.module_proxies";   // module id -> its require() proxy
inline constexpr const char* kRequestThreadsKey = "rhp.request_threads"; // weak set of request coroutines (coroutine.resume / close refuse them)
inline constexpr const char* kTaskKey = "rhp.task";                      // metatable of task handles (tasks.cpp)
inline constexpr const char* kSpanKey = "rhp.span";                      // metatable of typed views: host spans, slices, buffer views (views.cpp)
inline constexpr const char* kBufferKey = "rhp.buffer";                  // metatable of byte buffers and their slices (buffer.cpp)
inline constexpr const char* kHandleTagsKey = "rhp.handle_tags";         // handle type tag -> its metatable's name (stack.cpp)

// Fields of handle metatables (stack.cpp; the test bridge reads them).
inline constexpr const char* kTypeTagField = "__rhp_type";    // the C++ type (a light userdata tag)
inline constexpr const char* kMethodsField = "__rhp_methods"; // methods (name -> function)
inline constexpr const char* kGettersField = "__rhp_getters"; // properties (name -> getter(self))

// Field of lib proxies' metatables (lib_proxy.cpp): the debugger reads through these proxies only
// (their getters are C++), the test bridge swaps their members.
inline constexpr const char* kLibMarker = "__rhp_lib";

// Fields of struct view types' metatables (views.cpp).
inline constexpr const char* kViewTypeTagField = "__rhp_view_type"; // the C++ type (view_type_info::type_tag; not a handle's __rhp_type)
inline constexpr const char* kViewFieldsField = "__rhp_fields";     // name -> light userdata (field_desc)
inline constexpr const char* kViewOrderField = "__rhp_order";       // the field names in declaration order

// The test bridge: a global of the scratch environment of a sandbox with enable_testing (testing.cpp).
inline constexpr const char* kTestBridgeName = "__rhp_test";

} // namespace Rhp::script::detail
