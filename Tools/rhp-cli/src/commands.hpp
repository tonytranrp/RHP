#pragma once

// rhp-cli's subcommands, one translation unit per family; main.cpp parses and dispatches.

#include <string>
#include <vector>

#include "release_files.hpp"

namespace rhp_cli {

// keys.cpp
int keygen(const std::string& name, const std::string& out_path, const std::string& role_text, bool force);
int pubkey(const std::string& identity, const std::string& role_text);
int sign(const std::string& file, const std::string& identity);

// releases.cpp
int release_build(const release_spec& spec, const std::vector<std::string>& identities, const std::string& out_path);
int revoke_build(const revocation_spec& spec, const std::vector<std::string>& identities, const std::string& out_path);
int release_sign(const std::string& file, const std::string& identity);
int revoke_sign(const std::string& file, const std::string& identity);
int inspect(const std::string& path);

// test_command.cpp
int test_command(std::vector<std::string> args);

} // namespace rhp_cli
