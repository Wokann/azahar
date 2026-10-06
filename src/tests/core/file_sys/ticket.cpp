// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the misc/licenses/gplv2.txt file included.

#include <algorithm>
#include <cstring>
#include <vector>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include "common/alignment.h"
#include "core/file_sys/signature.h"
#include "core/file_sys/ticket.h"
#include "core/loader/loader.h"

namespace FileSys {
namespace {

// Entirely synthetic, unsigned test data. No console keys or account data are required.
std::vector<u8> MakeTicket(u32 signature_type) {
    const auto signature_size = GetSignatureSize(signature_type);
    const auto body_offset = Common::AlignUp(sizeof(u32) + signature_size, 0x40);
    constexpr std::size_t content_index_size = 0x40;
    std::vector<u8> data(body_offset + sizeof(Ticket::Body) + content_index_size);

    const u32_be type{signature_type};
    std::memcpy(data.data(), &type, sizeof(type));
    std::fill_n(data.begin() + sizeof(type), signature_size, 0xA5);

    Ticket::Body body{};
    body.issuer.fill(0x5A);
    body.ecc_public_key.fill(0x3C);
    body.version = 1;
    body.title_key.fill(0x96);
    body.ticket_id = 0x0102030405060708ULL;
    body.console_id = 0x11223344;
    body.title_id = 0x0004000DFFFFFFFFULL;
    body.ticket_title_version = 0x1234;
    body.eshop_account_id = 0x55667788;
    std::memcpy(data.data() + body_offset, &body, sizeof(body));

    Ticket::ContentIndex::MainHeader header{};
    header.always1 = 1;
    header.header_size = sizeof(header);
    header.context_index_size = content_index_size;
    header.index_headers_offset = sizeof(header);
    header.index_header_size = sizeof(Ticket::ContentIndex::IndexHeader);
    std::memcpy(data.data() + body_offset + sizeof(body), &header, sizeof(header));
    return data;
}

} // namespace

TEST_CASE("Ticket serialization preserves raw ticket data", "[core][file_sys][ticket]") {
    const auto signature_type =
        GENERATE(Rsa4096Sha1, Rsa2048Sha1, EllipticSha1, Rsa4096Sha256, Rsa2048Sha256, EcdsaSha256);
    const auto data = MakeTicket(signature_type);
    Ticket ticket;
    REQUIRE(ticket.Load(data) == Loader::ResultStatus::Success);
    CHECK(ticket.GetTitleID() == 0x0004000DFFFFFFFFULL);
    CHECK(ticket.GetTicketID() == 0x0102030405060708ULL);
    CHECK(ticket.GetVersion() == 0x1234);
    CHECK(ticket.Serialize() == data);
}

TEST_CASE("Ticket serialization excludes trailing data", "[core][file_sys][ticket]") {
    const auto ticket_data = MakeTicket(Rsa2048Sha256);
    auto data = ticket_data;
    data.insert(data.end(), 0x100, 0xCC);
    Ticket ticket;
    REQUIRE(ticket.Load(data) == Loader::ResultStatus::Success);
    CHECK(ticket.Serialize() == ticket_data);
    CHECK(ticket.Serialize().size() == 0x2E4);
}

TEST_CASE("Ticket rejects truncated data", "[core][file_sys][ticket]") {
    auto data = MakeTicket(Rsa2048Sha256);
    data.resize(data.size() - 1);
    Ticket ticket;
    CHECK(ticket.Load(data) == Loader::ResultStatus::Error);
}

} // namespace FileSys
