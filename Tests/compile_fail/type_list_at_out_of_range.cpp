// Indexing past the end of a type_list must not compile.
#include <rhp/utils/type_list.hpp>

using list = Rhp::utils::type_list<int, char>;
using ok = Rhp::utils::at_t<list, 1>;

#if defined(RHP_COMPILE_FAIL)
using bad = Rhp::utils::at_t<list, 2>;
#endif
