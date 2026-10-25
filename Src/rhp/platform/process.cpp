#include <cerrno>
#include <cstring>
#include <filesystem>
#include <format>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <rhp/build_config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/process.hpp>

#if defined(RHP_PLATFORM_WINDOWS)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#elif !defined(RHP_PLATFORM_IOS)
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace Rhp::platform {

#if defined(RHP_PLATFORM_WINDOWS)

namespace {

std::wstring widen(std::string_view s) {
    if (s.empty()) {
        return {};
    }
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

// One argument quoted the way CommandLineToArgvW (and the C runtime) splits it back.
void append_quoted(std::wstring& line, const std::wstring& arg) {
    if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        line += arg;
        return;
    }
    line += L'"';
    for (std::size_t i = 0;; ++i) {
        std::size_t backslashes = 0;
        while (i < arg.size() && arg[i] == L'\\') {
            ++i;
            ++backslashes;
        }
        if (i == arg.size()) {
            line.append(backslashes * 2, L'\\'); // before the closing quote
            break;
        }
        if (arg[i] == L'"') {
            line.append(backslashes * 2 + 1, L'\\');
        } else {
            line.append(backslashes, L'\\');
        }
        line += arg[i];
    }
    line += L'"';
}

} // namespace

result<int> run_process(const std::filesystem::path& program, std::span<const std::string> args) {
    std::filesystem::path exe = program;
    if (exe.has_parent_path()) {
        std::error_code ec;
        exe = std::filesystem::absolute(exe, ec); // a relative path with '/' isn't searched for
    }
    exe.make_preferred();
    std::wstring line;
    append_quoted(line, exe.wstring());
    for (const std::string& a : args) {
        line += L' ';
        append_quoted(line, widen(a));
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION info{};
    if (CreateProcessW(nullptr, line.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startup, &info) == 0) {
        return fail(errc::kNotFound, std::format("can't start {}: {}", program.generic_string(), std::system_category().message(static_cast<int>(GetLastError()))),
                    "run_process");
    }
    WaitForSingleObject(info.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(info.hProcess, &code);
    CloseHandle(info.hThread);
    CloseHandle(info.hProcess);
    return static_cast<int>(code);
}

#elif defined(RHP_PLATFORM_IOS)

result<int> run_process(const std::filesystem::path& program, std::span<const std::string>) {
    return fail(errc::kDisabled, "iOS apps can't start processes", program.generic_string());
}

#else

result<int> run_process(const std::filesystem::path& program, std::span<const std::string> args) {
    const std::string path = program.string();
    std::vector<std::string> owned{path};
    owned.insert(owned.end(), args.begin(), args.end());
    std::vector<char*> argv;
    for (std::string& a : owned) {
        argv.push_back(a.data());
    }
    argv.push_back(nullptr);
    const pid_t child = fork();
    if (child < 0) {
        return fail(errc::kRuntime, std::format("can't start {}: {}", path, std::strerror(errno)), "run_process");
    }
    if (child == 0) {
        execvp(argv[0], argv.data());
        _exit(127); // the shells' "command not found"
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return fail(errc::kRuntime, std::format("waiting for {}: {}", path, std::strerror(errno)), "run_process");
        }
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 1;
}

#endif

} // namespace Rhp::platform
