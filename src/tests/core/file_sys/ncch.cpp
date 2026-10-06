// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the misc/licenses/gplv2.txt file included.

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include "core/core.h"
#include "core/core_timing.h"
#include "core/file_sys/patch.h"
#include "core/hle/kernel/process.h"
#include "core/loader/ncch.h"
#include "core/memory.h"

TEST_CASE("NCCH reserves the entire codeset before patching", "[loader][ncch][memory]") {
    Core::Timing timing(1, 100);
    Core::System system;
    Memory::MemorySystem memory{system};
    Kernel::KernelSystem kernel(memory, timing, [] {}, Kernel::MemoryMode::NewProd, 1);
    auto codeset = kernel.CreateCodeSet("test", 0);
    ExHeader_CodeSetInfo layout{};
    layout.text = {0x100000, 2, 0x1800};
    layout.ro = {0x102000, 1, 0x800};
    layout.data = {0x103000, 1, 0x800};
    std::vector<u8> code(0x4000, 0xA5);

    SECTION("original bss allocation is preserved") {
        layout.bss_size = 0x1800;
        REQUIRE(Loader::ConfigureCodeSet(*codeset, layout, code) == Loader::ResultStatus::Success);
        CHECK(code.size() == 0x6000);
        CHECK(codeset->DataSegment().size == 0x3000);
    }
    SECTION("expanded data pages are zero filled without moving old addresses") {
        layout.data.num_max_pages = 4;
        layout.data.code_size = 0x4000;
        REQUIRE(Loader::ConfigureCodeSet(*codeset, layout, code) == Loader::ResultStatus::Success);
        CHECK(code.size() == 0x7000);
        CHECK(codeset->CodeSegment().addr == 0x100000);
        CHECK(codeset->RODataSegment().addr == 0x102000);
        CHECK(codeset->DataSegment().addr == 0x103000);
        CHECK(codeset->DataSegment().offset == 0x3000);

        const std::vector<u8> ips{'P', 'A', 'T', 'C', 'H', 0, 0x60, 0, 0, 1, 0x42, 'E', 'O', 'F'};
        CHECK(FileSys::Patch::ApplyIpsPatch(ips, code) == Loader::ResultStatus::Success);
        CHECK(code[0x6000] == 0x42);
        auto invalid_ips = ips;
        invalid_ips[6] = 0x70;
        CHECK(FileSys::Patch::ApplyIpsPatch(invalid_ips, code) ==
              Loader::ResultStatus::ErrorPatches);
        code[0x6000] = 0;
    }
    SECTION("a short code replacement still reserves the declared pages") {
        code.resize(0x1800);
        REQUIRE(Loader::ConfigureCodeSet(*codeset, layout, code) == Loader::ResultStatus::Success);
        CHECK(code.size() == 0x4000);
        CHECK(std::all_of(code.begin() + 0x1800, code.end(), [](u8 value) { return value == 0; }));
        return;
    }
    SECTION("oversized declarations do not allocate or truncate") {
        layout.data.num_max_pages = 0xFFFFFFFF;
        CHECK(Loader::ConfigureCodeSet(*codeset, layout, code) ==
              Loader::ResultStatus::ErrorInvalidFormat);
        CHECK(code.size() == 0x4000);
        return;
    }
    SECTION("bss rounding cannot overflow") {
        layout.bss_size = 0xFFFFFFFF;
        CHECK(Loader::ConfigureCodeSet(*codeset, layout, code) ==
              Loader::ResultStatus::ErrorInvalidFormat);
        CHECK(code.size() == 0x4000);
        return;
    }
    CHECK(std::all_of(code.begin(), code.begin() + 0x4000, [](u8 value) { return value == 0xA5; }));
    CHECK(std::all_of(code.begin() + 0x4000, code.end(), [](u8 value) { return value == 0; }));
}
