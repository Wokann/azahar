// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the misc/licenses/gplv2.txt file included.

#include <array>
#include <catch2/catch_test_macros.hpp>
#include "common/logging/log.h"
#include "core/core.h"
#include "core/core_timing.h"
#include "core/hle/kernel/errors.h"
#include "core/hle/kernel/process.h"
#include "core/hle/kernel/svc_wrapper.h"
#include "core/memory.h"

namespace {

constexpr VAddr source_address = 0x08000000;
constexpr VAddr target_address = 0x09000000;
constexpr u32 page_size = Memory::CITRA_PAGE_SIZE;
using Operation = Kernel::ProcessMemoryOperation;
using Permission = Kernel::VMAPermission;
using State = Kernel::MemoryState;

struct ProcessMemoryFixture {
    Core::Timing timing{1, 100};
    Core::System system;
    Memory::MemorySystem memory{system};
    Kernel::KernelSystem kernel{memory, timing, [] {}, Kernel::MemoryMode::NewProd, 1};
    Kernel::Process process{kernel};
    MemoryRef backing{std::make_shared<BufferMem>(3 * page_size)};

    ProcessMemoryFixture() {
        REQUIRE(process.vm_manager
                    .MapBackingMemory(source_address, backing, 3 * page_size, State::Private)
                    .Succeeded());
    }

    Result Control(VAddr target, VAddr source, u32 size, Operation operation, u32 permissions) {
        return process.ControlMemory(target, source, size, operation, permissions);
    }

    const Kernel::VirtualMemoryArea& Area(VAddr address) {
        return process.vm_manager.FindVMA(address)->second;
    }
};

class RegisterContext : public Kernel::SVCWrapper<RegisterContext> {
public:
    std::array<u32, 8> registers{};
    std::array<u32, 6> arguments{};

    u32 GetReg(std::size_t index) {
        return registers.at(index);
    }
    void SetReg(std::size_t index, u32 value) {
        registers.at(index) = value;
    }
    Result ControlProcessMemory(u32 process, u32 target, u32 source, u32 size, u32 operation,
                                u32 permissions) {
        arguments = {process, target, source, size, operation, permissions};
        return ResultSuccess;
    }
    void Call() {
        Wrap<&RegisterContext::ControlProcessMemory, 0x70>();
    }
};

} // namespace

TEST_CASE("ControlProcessMemory register ABI", "[kernel][svc]") {
    RegisterContext context;
    context.registers = {0x1234, target_address, source_address, page_size, 6, 7, 0x66, 0x77};
    const auto before = context.registers;
    context.Call();
    CHECK(context.arguments ==
          std::array<u32, 6>{0x1234, target_address, source_address, page_size, 6, 7});
    CHECK(context.registers[0] == ResultSuccess.raw);
    for (std::size_t index = 1; index < before.size(); ++index) {
        CHECK(context.registers[index] == before[index]);
    }
}

TEST_CASE("ControlProcessMemory validates arguments", "[kernel][memory][svc]") {
    ProcessMemoryFixture fixture;
    SECTION("unaligned destination") {
        CHECK(fixture.Control(source_address + 1, 0, page_size, Operation::Protect, 7) ==
              Kernel::ResultMisalignedAddress);
    }
    SECTION("unaligned source") {
        CHECK(fixture.Control(target_address, source_address + 1, page_size, Operation::Map, 7) ==
              Kernel::ResultMisalignedAddress);
    }
    SECTION("unaligned size") {
        CHECK(fixture.Control(source_address, 0, page_size - 1, Operation::Protect, 7) ==
              Kernel::ResultMisalignedSize);
    }
    SECTION("empty range") {
        CHECK(fixture.Control(source_address, 0, 0, Operation::Protect, 7).IsError());
    }
    SECTION("overflowing range") {
        CHECK(fixture.Control(0xFFFFF000, 0, 2 * page_size, Operation::Protect, 7) ==
              Kernel::ResultInvalidAddress);
        CHECK(fixture.Control(source_address, 0, 0xFFFFF000, Operation::Protect, 7) ==
              Kernel::ResultInvalidAddress);
        CHECK(fixture.Control(target_address, 0xFFFFF000, page_size, Operation::Map, 7) ==
              Kernel::ResultInvalidAddress);
    }
    SECTION("unsupported operation or flags") {
        for (const auto operation : {0u, 1u, 2u, 3u, 7u, 0x106u, 0x10006u}) {
            CHECK(fixture.Control(source_address, 0, page_size, static_cast<Operation>(operation),
                                  7) == Kernel::ResultInvalidCombination);
        }
    }
    SECTION("invalid permission bits or write without read") {
        for (const auto permissions : {2u, 6u, 8u, 0x100u, 0x10000000u}) {
            CHECK(fixture.Control(source_address, 0, page_size, Operation::Protect, permissions) ==
                  Kernel::ResultInvalidCombination);
        }
    }
    CHECK(fixture.Area(source_address).permissions == Permission::ReadWrite);
    CHECK(fixture.Area(source_address).meminfo_state == State::Private);
    CHECK(fixture.Area(target_address).type == Kernel::VMAType::Free);
}

TEST_CASE("ControlProcessMemory protects only the requested range", "[kernel][memory][svc]") {
    ProcessMemoryFixture fixture;
    SECTION("executable data page") {
        REQUIRE(fixture.Control(source_address + page_size, 0, page_size, Operation::Protect, 7) ==
                ResultSuccess);
        CHECK(fixture.Area(source_address).permissions == Permission::ReadWrite);
        CHECK(fixture.Area(source_address + page_size).permissions == Permission::ReadWriteExecute);
        CHECK(fixture.Area(source_address + 2 * page_size).permissions == Permission::ReadWrite);
        CHECK(fixture.Area(source_address + page_size).meminfo_state == State::Private);
    }
    SECTION("unmapped page causes no partial change") {
        CHECK(fixture.Control(source_address, 0, 4 * page_size, Operation::Protect, 7) ==
              Kernel::ResultInvalidAddressState);
        CHECK(fixture.Area(source_address).permissions == Permission::ReadWrite);
    }
    SECTION("code can become read execute") {
        REQUIRE(fixture.process.vm_manager
                    .ChangeMemoryState(source_address, page_size, State::Private,
                                       Permission::ReadWrite, State::Code, Permission::Read)
                    .IsSuccess());
        CHECK(fixture.Control(source_address, 0, page_size, Operation::Protect, 5) ==
              ResultSuccess);
        CHECK(fixture.Area(source_address).permissions == Permission::ReadExecute);
        CHECK(fixture.Area(source_address).meminfo_state == State::Code);
    }
}

TEST_CASE("ControlProcessMemory maps and unmaps executable aliases", "[kernel][memory][svc]") {
    ProcessMemoryFixture fixture;
    REQUIRE(fixture.Control(target_address, source_address, 3 * page_size, Operation::Map, 7) ==
            ResultSuccess);
    CHECK(fixture.Area(source_address).permissions == Permission::None);
    CHECK(fixture.Area(source_address).meminfo_state == State::Locked);
    CHECK(fixture.Area(target_address).permissions == Permission::ReadWriteExecute);
    CHECK(fixture.Area(target_address).meminfo_state == State::AliasCode);
    CHECK(fixture.Area(target_address).backing_memory.GetPtr() == fixture.backing.GetPtr());

    SECTION("a source cannot be mapped twice") {
        CHECK(fixture.Control(target_address + 0x10000, source_address, page_size, Operation::Map,
                              7) == Kernel::ResultInvalidAddressState);
    }
    SECTION("locked source cannot be made accessible") {
        CHECK(fixture.Control(source_address, 0, page_size, Operation::Protect, 3) ==
              Kernel::ResultInvalidAddressState);
        CHECK(fixture.Area(source_address).permissions == Permission::None);
    }
    SECTION("unmap restores the source") {
        REQUIRE(fixture.Control(target_address, source_address, 3 * page_size, Operation::Unmap,
                                3) == ResultSuccess);
        CHECK(fixture.Area(target_address).type == Kernel::VMAType::Free);
        CHECK(fixture.Area(source_address).meminfo_state == State::Private);
        CHECK(fixture.Area(source_address).permissions == Permission::ReadWrite);
    }
    SECTION("partial unmap handles a split alias") {
        REQUIRE(fixture.Control(target_address + page_size, 0, page_size, Operation::Protect, 5) ==
                ResultSuccess);
        REQUIRE(fixture.Control(target_address + page_size, source_address + page_size, page_size,
                                Operation::Unmap, 3) == ResultSuccess);
        CHECK(fixture.Area(target_address + page_size).type == Kernel::VMAType::Free);
        CHECK(fixture.Area(source_address + page_size).meminfo_state == State::Private);
        CHECK(fixture.Area(source_address).meminfo_state == State::Locked);
        CHECK(fixture.Area(source_address + 2 * page_size).meminfo_state == State::Locked);
    }
    SECTION("wrong source offset cannot remove the alias") {
        CHECK(fixture.Control(target_address, source_address + page_size, page_size,
                              Operation::Unmap, 3) == Kernel::ResultInvalidAddressState);
        CHECK(fixture.Area(target_address).meminfo_state == State::AliasCode);
        CHECK(fixture.Area(source_address).meminfo_state == State::Locked);
    }
    SECTION("a range extending past the source leaves mappings unchanged") {
        CHECK(fixture.Control(target_address, source_address, 4 * page_size, Operation::Unmap, 3) ==
              Kernel::ResultInvalidAddressState);
        CHECK(fixture.Area(target_address).meminfo_state == State::AliasCode);
        CHECK(fixture.Area(source_address).meminfo_state == State::Locked);
    }
}

TEST_CASE("ControlProcessMemory rejects invalid mapping sources and targets",
          "[kernel][memory][svc]") {
    ProcessMemoryFixture fixture;
    SECTION("occupied destination") {
        REQUIRE(fixture.process.vm_manager
                    .MapBackingMemory(target_address,
                                      MemoryRef{std::make_shared<BufferMem>(page_size)}, page_size,
                                      State::Private)
                    .Succeeded());
        CHECK(fixture.Control(target_address, source_address, page_size, Operation::Map, 7) ==
              Kernel::ResultInvalidAddressState);
    }
    SECTION("read only source") {
        REQUIRE(
            fixture.process.vm_manager.ReprotectRange(source_address, page_size, Permission::Read)
                .IsSuccess());
        CHECK(fixture.Control(target_address, source_address, page_size, Operation::Map, 7) ==
              Kernel::ResultInvalidAddressState);
    }
    SECTION("unmapped source") {
        CHECK(fixture.Control(target_address, source_address + 3 * page_size, page_size,
                              Operation::Map, 7) == Kernel::ResultInvalidAddressState);
    }
    SECTION("overlapping source and destination") {
        CHECK(fixture.Control(source_address + page_size, source_address, 2 * page_size,
                              Operation::Map, 7) == Kernel::ResultInvalidAddress);
    }
    CHECK(fixture.Area(source_address).meminfo_state == State::Private);
}

TEST_CASE("ControlProcessMemory aliases fragmented backing memory", "[kernel][memory][svc]") {
    ProcessMemoryFixture fixture;
    REQUIRE(
        fixture.process.vm_manager.UnmapRange(source_address + page_size, page_size).IsSuccess());
    MemoryRef middle{std::make_shared<BufferMem>(page_size)};
    REQUIRE(fixture.process.vm_manager
                .MapBackingMemory(source_address + page_size, middle, page_size, State::Private)
                .Succeeded());
    REQUIRE(fixture.Control(target_address, source_address, 3 * page_size, Operation::Map, 7) ==
            ResultSuccess);
    CHECK(fixture.Area(target_address + page_size).backing_memory.GetPtr() == middle.GetPtr());
    REQUIRE(fixture.Control(target_address, source_address, 3 * page_size, Operation::Unmap, 3) ==
            ResultSuccess);
    CHECK(fixture.Area(target_address).type == Kernel::VMAType::Free);
    CHECK(fixture.Area(source_address).meminfo_state == State::Private);
    CHECK(fixture.Area(source_address + page_size).meminfo_state == State::Private);
    CHECK(fixture.Area(source_address + 2 * page_size).meminfo_state == State::Private);
}

TEST_CASE("ControlProcessMemory rejects unrelated aliases", "[kernel][memory][svc]") {
    ProcessMemoryFixture fixture;
    const auto other_backing = MemoryRef{std::make_shared<BufferMem>(page_size)};
    REQUIRE(fixture.process.vm_manager
                .MapBackingMemory(target_address, other_backing, page_size, State::AliasCode)
                .Succeeded());
    REQUIRE(fixture.process.vm_manager
                .ChangeMemoryState(source_address, page_size, State::Private, Permission::ReadWrite,
                                   State::Locked, Permission::None)
                .IsSuccess());
    CHECK(fixture.Control(target_address, source_address, page_size, Operation::Unmap, 3) ==
          Kernel::ResultInvalidAddressState);
    CHECK(fixture.Area(target_address).meminfo_state == State::AliasCode);
    CHECK(fixture.Area(source_address).meminfo_state == State::Locked);
}

TEST_CASE("ControlProcessMemory supports in place aliases", "[kernel][memory][svc]") {
    ProcessMemoryFixture fixture;
    REQUIRE(fixture.Control(source_address, source_address, page_size, Operation::Map, 7) ==
            ResultSuccess);
    CHECK(fixture.Area(source_address).meminfo_state == State::AliasCode);
    CHECK(fixture.Area(source_address).permissions == Permission::ReadWriteExecute);
    REQUIRE(fixture.Control(source_address, source_address, page_size, Operation::Unmap, 3) ==
            ResultSuccess);
    CHECK(fixture.Area(source_address).meminfo_state == State::Private);
    CHECK(fixture.Area(source_address).permissions == Permission::ReadWrite);
}
