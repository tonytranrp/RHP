#pragma once

// rhp-cli's subcommands. Each add_<name> adds one to the command line, with an options struct of its
// own that the function running it (run_<name>, file-local) reads once it is parsed; the families
// live in a translation unit each, and main.cpp adds them in help order and runs the one given.

#include <functional>
#include <utility>
#include <vector>

#include <CLI/CLI.hpp>

namespace rhp_cli {

// A subcommand: its CLI11 node and what runs it once parsed (the exit status).
struct command {
    command(CLI::App* parsed_by, std::function<int()> runs, bool interruptible = true) : cli(parsed_by), run(std::move(runs)), catches_interrupt(interruptible) {}

    CLI::App* cli;
    std::function<int()> run;
    // Ctrl+C sets rhp-cli's interrupted flag (cancels a running script) instead of ending rhp-cli.
    bool catches_interrupt;
};
using command_list = std::vector<command>;

// keys.cpp: identity files and script signatures (no network).
void add_keygen(CLI::App& app, command_list& out);
void add_pubkey(CLI::App& app, command_list& out);
void add_sign(CLI::App& app, command_list& out);

// certs.cpp: operator CAs and certificates (no network).
void add_ca(CLI::App& app, command_list& out);
void add_cert(CLI::App& app, command_list& out);

// fleet.cpp: DNS-SD discovery, fleet broadcasts and rollouts.
void add_discover(CLI::App& app, command_list& out);
void add_fleet(CLI::App& app, command_list& out);
void add_rollout(CLI::App& app, command_list& out);

// releases.cpp: `release build|sign|inspect|apply|status|confirm|deactivate`, `revoke build|sign|apply`.
void add_release(CLI::App& app, command_list& out);
void add_revoke(CLI::App& app, command_list& out);

// trust.cpp: `root init|next|sign|show`, `revoke-identity`, `trust push`.
void add_root(CLI::App& app, command_list& out);
void add_revoke_identity(CLI::App& app, command_list& out);
void add_trust(CLI::App& app, command_list& out);

// test_command.cpp: the offline Lua test runner.
void add_test(CLI::App& app, command_list& out);

} // namespace rhp_cli
