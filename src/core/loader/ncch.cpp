// Copyright 2014-2026 Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the misc/licenses/gplv2.txt file included.

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <vector>
#include <fmt/format.h>
#include "common/file_derived.h"
#include "common/file_util.h"
#include "common/literals.h"
#include "common/logging/log.h"
#include "common/settings.h"
#include "common/string_util.h"
#include "common/swap.h"
#include "core/core.h"
#include "core/file_sys/ncch_container.h"
#include "core/file_sys/title_metadata.h"
#include "core/hle/kernel/kernel.h"
#include "core/hle/kernel/process.h"
#include "core/hle/kernel/resource_limit.h"
#include "core/hle/service/am/am.h"
#include "core/hle/service/cfg/cfg.h"
#include "core/hle/service/fs/archive.h"
#include "core/hle/service/fs/fs_user.h"
#include "core/hw/unique_data.h"
#include "core/loader/ncch.h"
#include "core/loader/smdh.h"
#include "core/memory.h"
#include "core/system_titles.h"
#include "network/network.h"

namespace Loader {

using namespace Common::Literals;
static constexpr u64 UPDATE_TID_HIGH = 0x0004000e00000000;
static constexpr u64 DLP_CHILD_TID_HIGH = 0x0004000100000000;

ResultStatus ConfigureCodeSet(Kernel::CodeSet& codeset, const ExHeader_CodeSetInfo& layout,
                              std::vector<u8>& code) {
    const u64 bss_size = (static_cast<u64>(layout.bss_size) + Memory::CITRA_PAGE_MASK) &
                         ~static_cast<u64>(Memory::CITRA_PAGE_MASK);
    const std::array segment_info{layout.text, layout.ro, layout.data};
    const std::array<u64, 3> segment_sizes{
        static_cast<u64>(layout.text.num_max_pages) * Memory::CITRA_PAGE_SIZE,
        static_cast<u64>(layout.ro.num_max_pages) * Memory::CITRA_PAGE_SIZE,
        static_cast<u64>(layout.data.num_max_pages) * Memory::CITRA_PAGE_SIZE + bss_size,
    };
    u64 image_size = 0;
    for (std::size_t index = 0; index < segment_info.size(); ++index) {
        const auto address = segment_info[index].address;
        if ((address & Memory::CITRA_PAGE_MASK) != 0 || address >= Kernel::VMManager::MAX_ADDRESS ||
            segment_sizes[index] > Kernel::VMManager::MAX_ADDRESS - address) {
            LOG_ERROR(Loader, "Invalid NCCH codeset segment {}", index);
            return ResultStatus::ErrorInvalidFormat;
        }
        image_size += segment_sizes[index];
    }
    // Preserve the previous .code + .bss allocation when it is larger than the header layout.
    image_size = std::max(image_size, static_cast<u64>(code.size()) + bss_size);
    if (image_size > Memory::FCRAM_N3DS_SIZE) {
        LOG_ERROR(Loader, "NCCH codeset is too large: 0x{:X}", image_size);
        return ResultStatus::ErrorInvalidFormat;
    }

    std::size_t offset = 0;
    for (std::size_t index = 0; index < segment_info.size(); ++index) {
        codeset.segments[index].offset = offset;
        codeset.segments[index].addr = segment_info[index].address;
        codeset.segments[index].size = static_cast<u32>(segment_sizes[index]);
        offset += codeset.segments[index].size;
    }
    // A mod's exheader can reserve more pages than the original .code contains. IPS may write
    // within those declared pages, but must still be rejected outside this allocated image.
    code.resize(static_cast<std::size_t>(image_size), 0);
    return ResultStatus::Success;
}

FileType AppLoader_NCCH::IdentifyType(FileUtil::IOFileBase* in_file) {
    u32 magic{};

    auto file = FileSys::NCCHContainer::AutoOpenNCCHNCSD(in_file);

    if (file->ReadAtArray<u32>(&magic, 1, 0x100)) {
        if (FileUtil::MakeMagic('N', 'C', 'S', 'D') == magic)
            return FileType::CCI;

        if (FileUtil::MakeMagic('N', 'C', 'C', 'H') == magic)
            return FileType::CXI;
    }

    return FileType::Error;
}

std::pair<std::optional<u32>, ResultStatus> AppLoader_NCCH::LoadCoreVersion() {
    if (!is_loaded) {
        ResultStatus res = base_ncch.Load();
        if (res != ResultStatus::Success) {
            return std::make_pair(std::nullopt, res);
        }
    }

    // Provide the core version from the exheader.
    auto& ncch_caps = overlay_ncch->exheader_header.arm11_system_local_caps;
    return std::make_pair(ncch_caps.core_version, ResultStatus::Success);
}

std::pair<std::optional<Kernel::MemoryMode>, ResultStatus> AppLoader_NCCH::LoadKernelMemoryMode() {
    if (!is_loaded) {
        ResultStatus res = base_ncch.Load();
        if (res != ResultStatus::Success) {
            return std::make_pair(std::nullopt, res);
        }
    }
    if (memory_mode_override.has_value()) {
        return std::make_pair(memory_mode_override, ResultStatus::Success);
    }

    // Provide the memory mode from the exheader.
    auto& ncch_caps = overlay_ncch->exheader_header.arm11_system_local_caps;
    auto mode = static_cast<Kernel::MemoryMode>(ncch_caps.system_mode.Value());
    return std::make_pair(mode, ResultStatus::Success);
}

std::pair<std::optional<Kernel::New3dsHwCapabilities>, ResultStatus>
AppLoader_NCCH::LoadNew3dsHwCapabilities() {
    if (!is_loaded) {
        ResultStatus res = base_ncch.Load();
        if (res != ResultStatus::Success) {
            return std::make_pair(std::nullopt, res);
        }
    }

    // Provide the capabilities from the exheader.
    auto& ncch_caps = overlay_ncch->exheader_header.arm11_system_local_caps;
    auto caps = Kernel::New3dsHwCapabilities{
        ncch_caps.enable_l2_cache != 0,
        ncch_caps.enable_804MHz_cpu != 0,
        static_cast<Kernel::New3dsMemoryMode>(ncch_caps.n3ds_mode),
    };
    return std::make_pair(std::move(caps), ResultStatus::Success);
}

bool AppLoader_NCCH::IsN3DSExclusive() {
    if (!is_loaded) {
        ResultStatus res = base_ncch.Load();
        if (res != ResultStatus::Success) {
            return false;
        }
    }

    std::vector<u8> smdh_buffer;
    if (ReadIcon(smdh_buffer) == ResultStatus::Success && IsValidSMDH(smdh_buffer)) {
        SMDH* smdh = reinterpret_cast<SMDH*>(smdh_buffer.data());
        return smdh->flags.n3ds_exclusive != 0;
    }

    return false;
}

ResultStatus AppLoader_NCCH::LoadExec(std::shared_ptr<Kernel::Process>& process) {
    using Kernel::CodeSet;

    if (!is_loaded)
        return ResultStatus::ErrorNotLoaded;

    std::vector<u8> code;
    u64_le program_id;
    if (ResultStatus::Success == ReadCode(code) &&
        ResultStatus::Success == ReadProgramId(program_id)) {
        if (IsGbaVirtualConsole(code)) {
            LOG_ERROR(Loader, "Encountered unsupported GBA Virtual Console code section.");
            return ResultStatus::ErrorGbaTitle;
        }

        std::string process_name = Common::StringFromFixedZeroTerminatedBuffer(
            (const char*)overlay_ncch->exheader_header.codeset_info.name, 8);

        std::shared_ptr<CodeSet> codeset = system.Kernel().CreateCodeSet(process_name, program_id);

        const auto layout_result =
            ConfigureCodeSet(*codeset, overlay_ncch->exheader_header.codeset_info, code);
        if (layout_result != ResultStatus::Success) {
            return layout_result;
        }

        // Apply patches now that the entire codeset (including .bss) has been allocated
        const ResultStatus patch_result = overlay_ncch->ApplyCodePatch(code);
        if (patch_result != ResultStatus::Success && patch_result != ResultStatus::ErrorNotUsed)
            return patch_result;

        codeset->entrypoint = codeset->CodeSegment().addr;
        codeset->memory = std::move(code);

        process = system.Kernel().CreateProcess(std::move(codeset));

        // Attach a resource limit to the process based on the resource limit category
        const auto category = static_cast<Kernel::ResourceLimitCategory>(
            overlay_ncch->exheader_header.arm11_system_local_caps.resource_limit_category);
        process->resource_limit = system.Kernel().ResourceLimit().GetForCategory(category);

        // Update application max cpu setting. PM module uses the launch flags to determine
        // this, but using the resource limit category is close enough.
        if (category == Kernel::ResourceLimitCategory::Application) {
            process->resource_limit->ApplyAppMaxCPUSetting(
                process, overlay_ncch->exheader_header.arm11_system_local_caps.schedule_mode,
                overlay_ncch->exheader_header.arm11_system_local_caps.max_cpu);
        }

        // When running N3DS-unaware titles pm will lie about the amount of memory available.
        // This means RESLIMIT_COMMIT = APPMEMALLOC doesn't correspond to the actual size of
        // APPLICATION. See:
        // https://github.com/LumaTeam/Luma3DS/blob/e2778a45/sysmodules/pm/source/launch.c#L237
        auto& ncch_caps = overlay_ncch->exheader_header.arm11_system_local_caps;
        const auto o3ds_mode = *LoadKernelMemoryMode().first;
        const auto n3ds_mode = static_cast<Kernel::New3dsMemoryMode>(ncch_caps.n3ds_mode);
        const bool is_new_3ds = Settings::values.is_new_3ds.GetValue();
        if (is_new_3ds && n3ds_mode == Kernel::New3dsMemoryMode::Legacy &&
            category == Kernel::ResourceLimitCategory::Application) {
            u64 new_limit = 0;
            switch (o3ds_mode) {
            case Kernel::MemoryMode::Prod:
                new_limit = 64_MiB;
                break;
            case Kernel::MemoryMode::Dev1:
                new_limit = 96_MiB;
                break;
            case Kernel::MemoryMode::Dev2:
                new_limit = 80_MiB;
                break;
            default:
                break;
            }
            process->resource_limit->SetLimitValue(Kernel::ResourceLimitType::Commit,
                                                   static_cast<s32>(new_limit));
        }

        // Set the default CPU core for this process
        process->ideal_processor =
            overlay_ncch->exheader_header.arm11_system_local_caps.ideal_processor;

        // Copy data while converting endianness
        using KernelCaps = std::array<u32, ExHeader_ARM11_KernelCaps::NUM_DESCRIPTORS>;
        KernelCaps kernel_caps;
        std::copy_n(overlay_ncch->exheader_header.arm11_kernel_caps.descriptors, kernel_caps.size(),
                    begin(kernel_caps));
        process->ParseKernelCaps(kernel_caps.data(), kernel_caps.size());

        s32 priority = overlay_ncch->exheader_header.arm11_system_local_caps.priority;
        u32 stack_size = overlay_ncch->exheader_header.codeset_info.stack_size;

        // On real HW this is done with FS:Reg, but we can be lazy
        auto fs_user = system.ServiceManager().GetService<Service::FS::FS_USER>("fs:USER");
        fs_user->RegisterProgramInfo(process->process_id, process->codeset->program_id, filepath);

        Service::FS::FS_USER::ProductInfo product_info{};
        std::memcpy(product_info.product_code.data(), overlay_ncch->ncch_header.product_code,
                    product_info.product_code.size());
        std::memcpy(&product_info.remaster_version,
                    overlay_ncch->exheader_header.codeset_info.flags.remaster_version,
                    sizeof(product_info.remaster_version));
        product_info.maker_code = overlay_ncch->ncch_header.maker_code;
        fs_user->RegisterProductInfo(process->process_id, product_info);

        process->Run(priority, stack_size);
        return ResultStatus::Success;
    }
    return ResultStatus::Error;
}

void AppLoader_NCCH::ParseRegionLockoutInfo(u64 program_id) {
    if (Settings::values.region_value.GetValue() != Settings::REGION_VALUE_AUTO_SELECT) {
        return;
    }

    preferred_regions.clear();

    std::vector<u8> smdh_buffer;
    if (ReadIcon(smdh_buffer) == ResultStatus::Success && smdh_buffer.size() >= sizeof(SMDH)) {
        SMDH smdh;
        std::memcpy(&smdh, smdh_buffer.data(), sizeof(SMDH));
        u32 region_lockout = smdh.region_lockout;
        constexpr u32 REGION_COUNT = 7;
        for (u32 region = 0; region < REGION_COUNT; ++region) {
            if (region_lockout & 1) {
                preferred_regions.push_back(region);
            }
            region_lockout >>= 1;
        }
    } else {
        const auto region = Core::GetSystemTitleRegion(program_id);
        if (region.has_value()) {
            preferred_regions.push_back(region.value());
        }
    }
}

bool AppLoader_NCCH::IsGbaVirtualConsole(std::span<const u8> code) {
    if (code.size() < 0x10) [[unlikely]] {
        return false;
    }

    u32 gbaVcHeader[2];
    std::memcpy(gbaVcHeader, code.data() + code.size() - 0x10, sizeof(gbaVcHeader));
    return gbaVcHeader[0] == FileUtil::MakeMagic('.', 'C', 'A', 'A') && gbaVcHeader[1] == 1;
}

ResultStatus AppLoader_NCCH::Load(std::shared_ptr<Kernel::Process>& process) {
    u64_le ncch_program_id;

    if (is_loaded)
        return ResultStatus::ErrorAlreadyLoaded;

    ResultStatus result = base_ncch.Load();
    if (result != ResultStatus::Success)
        return result;

    ReadProgramId(ncch_program_id);
    std::string program_id{fmt::format("{:016X}", ncch_program_id)};

    LOG_INFO(Loader, "Program ID: {}", program_id);

    bool is_dlp_child = (ncch_program_id & 0xFFFFFFFF00000000) == DLP_CHILD_TID_HIGH;

    if (!is_dlp_child) {
        u64 update_tid = (ncch_program_id & 0xFFFFFFFFULL) | UPDATE_TID_HIGH;
        update_ncch.OpenFile(
            Service::AM::GetTitleContentPath(Service::FS::MediaType::SDMC, update_tid));
        result = update_ncch.Load();
        if (result == ResultStatus::Success) {
            overlay_ncch = &update_ncch;
        }
    }

    if (auto room_member = Network::GetRoomMember().lock()) {
        Network::GameInfo game_info;
        ReadTitle(game_info.name);
        game_info.id = ncch_program_id;
        room_member->SendGameInfo(game_info);
    }

    is_loaded = true; // Set state to loaded

    result = LoadExec(process); // Load the executable into memory for booting
    if (ResultStatus::Success != result)
        return result;

    system.ArchiveManager().RegisterSelfNCCH(*this);

    ParseRegionLockoutInfo(ncch_program_id);

    return ResultStatus::Success;
}

ResultStatus AppLoader_NCCH::IsExecutable(bool& out_executable) {
    Loader::ResultStatus result = overlay_ncch->Load();
    if (result != Loader::ResultStatus::Success)
        return result;

    out_executable = overlay_ncch->ncch_header.is_executable != 0;
    return ResultStatus::Success;
}

ResultStatus AppLoader_NCCH::ReadCode(std::vector<u8>& buffer) {
    return overlay_ncch->LoadSectionExeFS(".code", buffer);
}

ResultStatus AppLoader_NCCH::ReadIcon(std::vector<u8>& buffer) {
    return overlay_ncch->LoadSectionExeFS("icon", buffer);
}

ResultStatus AppLoader_NCCH::ReadBanner(std::vector<u8>& buffer) {
    return overlay_ncch->LoadSectionExeFS("banner", buffer);
}

ResultStatus AppLoader_NCCH::ReadLogo(std::vector<u8>& buffer) {
    return overlay_ncch->LoadSectionExeFS("logo", buffer);
}

ResultStatus AppLoader_NCCH::ReadProgramId(u64& out_program_id) {
    ResultStatus result = base_ncch.ReadProgramId(out_program_id);
    if (result != ResultStatus::Success)
        return result;

    return ResultStatus::Success;
}

ResultStatus AppLoader_NCCH::ReadExtdataId(u64& out_extdata_id) {
    ResultStatus result = base_ncch.ReadExtdataId(out_extdata_id);
    if (result != ResultStatus::Success)
        return result;

    return ResultStatus::Success;
}

ResultStatus AppLoader_NCCH::ReadRomFS(std::shared_ptr<FileSys::RomFSReader>& romfs_file) {
    return base_ncch.ReadRomFS(romfs_file);
}

ResultStatus AppLoader_NCCH::ReadUpdateRomFS(std::shared_ptr<FileSys::RomFSReader>& romfs_file) {
    ResultStatus result = update_ncch.ReadRomFS(romfs_file);

    if (result != ResultStatus::Success)
        return base_ncch.ReadRomFS(romfs_file);

    return ResultStatus::Success;
}

ResultStatus AppLoader_NCCH::DumpRomFS(const std::string& target_path) {
    return base_ncch.DumpRomFS(target_path);
}

ResultStatus AppLoader_NCCH::DumpUpdateRomFS(const std::string& target_path) {
    u64 program_id;
    ReadProgramId(program_id);
    u64 update_tid = (program_id & 0xFFFFFFFFULL) | UPDATE_TID_HIGH;
    update_ncch.OpenFile(
        Service::AM::GetTitleContentPath(Service::FS::MediaType::SDMC, update_tid));
    return update_ncch.DumpRomFS(target_path);
}

ResultStatus AppLoader_NCCH::ReadTitle(std::string& title) {
    std::vector<u8> data;
    Loader::SMDH smdh;
    ReadIcon(data);

    if (!Loader::IsValidSMDH(data)) {
        return ResultStatus::ErrorInvalidFormat;
    }

    std::memcpy(&smdh, data.data(), sizeof(Loader::SMDH));

    const auto& short_title = smdh.GetShortTitle(SMDH::TitleLanguage::English);
    auto title_end = std::find(short_title.begin(), short_title.end(), u'\0');
    title = Common::UTF16ToUTF8(std::u16string{short_title.begin(), title_end});

    return ResultStatus::Success;
}

AppLoader::CompressFileInfo AppLoader_NCCH::GetCompressFileInfo() {
    CompressFileInfo info{};
    if (base_ncch.LoadHeader() != ResultStatus::Success) {
        info.is_supported = false;
        return info;
    }
    info.is_supported = true;
    info.is_compressed = base_ncch.IsFileCompressed();
    if (base_ncch.IsNCSD()) {
        info.underlying_magic = std::array<u8, 4>({'N', 'C', 'S', 'D'});
        info.recommended_compressed_extension = "zcci";
        info.recommended_uncompressed_extension = "cci";
    } else {
        info.underlying_magic = std::array<u8, 4>({'N', 'C', 'C', 'H'});
        info.recommended_compressed_extension = "zcxi";
        info.recommended_uncompressed_extension = "cxi";
    }
    std::vector<u8> title_info_vec(sizeof(Service::AM::TitleInfo));
    Service::AM::TitleInfo* title_info =
        reinterpret_cast<Service::AM::TitleInfo*>(title_info_vec.data());
    title_info->tid = base_ncch.ncch_header.program_id;
    title_info->version = base_ncch.ncch_header.version;
    title_info->size =
        base_ncch.ncch_header.content_size * base_ncch.ncch_header.GetContentUnitSize();
    title_info->unused = title_info->type = 0;
    info.default_metadata.emplace("titleinfo", title_info_vec);

    return info;
}

bool AppLoader_NCCH::IsFileCompressed() {
    if (base_ncch.LoadHeader() != ResultStatus::Success) {
        return false;
    }
    return base_ncch.IsFileCompressed();
}

} // namespace Loader
