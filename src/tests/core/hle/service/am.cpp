// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the misc/licenses/gplv2.txt file included.

#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include "common/file_util.h"
#include "core/core.h"
#include "core/core_timing.h"
#include "core/hle/ipc.h"
#include "core/hle/kernel/hle_ipc.h"
#include "core/hle/kernel/process.h"
#include "core/hle/kernel/server_session.h"
#include "core/hle/service/am/am_net.h"

namespace Service::AM {

TEST_CASE("GetRightsOnlyTicketData rejects invalid exports", "[core][service][am][ticket]") {
    Core::Timing timing(1, 100);
    Core::System system;
    Memory::MemorySystem memory{system};
    Kernel::KernelSystem kernel(memory, timing, [] {}, Kernel::MemoryMode::NewProd, 1);
    auto [server, client] = kernel.CreateSessionPair();
    Kernel::HLERequestContext context(kernel, std::move(server), nullptr);
    auto process = kernel.CreateProcess(kernel.CreateCodeSet("", 0));
    AM_NET service{nullptr};

    auto output_mem = std::make_shared<BufferMem>(Memory::CITRA_PAGE_SIZE);
    std::fill(output_mem->Vector().begin(), output_mem->Vector().end(), 0xA5);
    const auto original_output = output_mem->Vector();
    constexpr VAddr target_address = 0x10000000;
    constexpr u32 buffer_size = Memory::CITRA_PAGE_SIZE;
    REQUIRE(process->vm_manager
                .MapBackingMemory(target_address, MemoryRef{output_mem}, buffer_size,
                                  Kernel::MemoryState::Private)
                .Code() == ResultSuccess);

    // These IDs are synthetic. The test never imports or changes a console's tickets.
    constexpr u64 title_id = 0x0004000DFFFFFFFFULL;
    constexpr u64 ticket_id = 0x0102030405060708ULL;
    u32 declared_size = buffer_size;
    Result expected_result = ResultSuccess;

    SECTION("declared size exceeds the mapped buffer") {
        declared_size = buffer_size + 1;
        expected_result = Result(ErrorDescription::InvalidSize, ErrorModule::AM,
                                 ErrorSummary::InvalidArgument, ErrorLevel::Usage);
    }
    SECTION("the requested ticket is missing") {
        REQUIRE_FALSE(FileUtil::Exists(GetTicketPath(title_id, ticket_id)));
        expected_result = Result(ErrorDescription::NotFound, ErrorModule::AM,
                                 ErrorSummary::InvalidState, ErrorLevel::Permanent);
    }

    const u32_le input[]{
        IPC::MakeHeader(0x0821, 5, 2),
        declared_size,
        static_cast<u32>(title_id),
        static_cast<u32>(title_id >> 32),
        static_cast<u32>(ticket_id),
        static_cast<u32>(ticket_id >> 32),
        IPC::MappedBufferDesc(buffer_size, IPC::W),
        target_address,
    };
    context.PopulateFromIncomingCommandBuffer(input, process);
    service.HandleSyncRequest(context);

    std::array<u32_le, IPC::COMMAND_BUFFER_LENGTH> output{};
    REQUIRE(context.WriteToOutgoingCommandBuffer(output.data(), *process) == ResultSuccess);
    CHECK(output[0] == IPC::MakeHeader(0x0821, 2, 2));
    CHECK(output[1] == expected_result.raw);
    CHECK(output[2] == 0);
    CHECK(output[3] == IPC::MappedBufferDesc(buffer_size, IPC::W));
    CHECK(output[4] == target_address);
    CHECK(output_mem->Vector() == original_output);
}

} // namespace Service::AM
