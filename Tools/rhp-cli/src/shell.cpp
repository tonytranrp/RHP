#include "shell.hpp"

namespace rhp_cli {

// The one instantiation rhp-cli uses (main.cpp sees it as extern): its members compile here, in
// parallel with main.cpp, instead of inside it.
template class shell<cli_cfg>;

} // namespace rhp_cli
