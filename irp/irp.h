#pragma once
#include "../includes.h"


struct IRP_SCAN_RESULT {
    bool hooked;
    PVOID handler;
    PDRIVER_OBJECT drv;
    const char* info;
};

struct driver_list {
    PDRIVER_OBJECT* drivers;
    ULONG count;
    ULONG capacity;
};

namespace PRIDE {

    inline POBJECT_HEADER get_object_header(PVOID object) {
        return (POBJECT_HEADER)((ULONG_PTR)object - sizeof(OBJECT_HEADER));
    }

    inline bool addr_in_range(PVOID addr, PVOID base, ULONG size) {
        ULONG_PTR a = (ULONG_PTR)addr;
        ULONG_PTR b = (ULONG_PTR)base;
        return a >= b && a < (b + size);
    }

    inline bool check_text_section(PVOID addr, PVOID base) {
        if (!addr || !base) return false;

        __try {
            auto dos = (PIMAGE_DOS_HEADER)base;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

            auto nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

            auto section = IMAGE_FIRST_SECTION(nt);
            for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {

                /*
                * we accept .text, TEXT, and PAGE (which is paged code).
                * anything else like .data or .rdata is weird for exec, like discardable sections. maybe add a flag for them in discard sections specifically later on?
                */

                bool is_valid_name = (
                    *(ULONG*)section[i].Name == 'xet.' ||  /* .text */
                    *(ULONG*)section[i].Name == 'TEXT' ||  /* TEXT */
                    *(ULONG*)section[i].Name == 'EGAP'  /* PAGE */
                    );

                if (is_valid_name) {
                    ULONG_PTR start = (ULONG_PTR)base + section[i].VirtualAddress;
                    ULONG_PTR end = start + section[i].Misc.VirtualSize;
                    ULONG_PTR a = (ULONG_PTR)addr;

                    /* if the address is inside this valid section, we're good */
                    if (a >= start && a < end) {
                        return true;
                    }
                }

            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
        return false;
    }

    inline PSYSTEM_MODULE_INFORMATION query_drivers() {
        ULONG size = 0;
        ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
        if (!size) return nullptr;

        auto info = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, size, 'prid');
        if (!info) return nullptr;

        if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, info, size, &size))) {
            ExFreePoolWithTag(info, 'prid');
            return nullptr;
        }
        return info;
    }
    
    inline const char* get_driver_name(PDRIVER_OBJECT drv, PSYSTEM_MODULE_INFORMATION mods) {
        if (!drv || !mods) return "unknown";

        __try {
            /* try to get name from driver object first */
            if (drv->DriverName.Buffer && drv->DriverName.Length > 0) {
                /* drivername is unicode, we need to find it in mods list for ascii name */
            }

            /* match by driverstart to get the module name */
            for (ULONG i = 0; i < mods->Count; i++) {
                if (drv->DriverStart == mods->Module[i].ImageBase) {
                    /* module name is full path, get just filename */
                    const char* full_path = (const char*)mods->Module[i].FullPathName;
                    const char* name = full_path;

                    /* find last backslash */
                    for (int j = 0; full_path[j] != '\0'; j++) {
                        if (full_path[j] == '\\') {
                            name = &full_path[j + 1];
                        }
                    }
                    return name;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return "exception";
        }

        return "not_in_module_list";
    }

    inline const char* get_module_name_for_addr(PVOID addr, PSYSTEM_MODULE_INFORMATION mods) {
        if (!addr || !mods) return "unknown";

        __try {
            for (ULONG i = 0; i < mods->Count; i++) {
                if (addr_in_range(addr, mods->Module[i].ImageBase, mods->Module[i].ImageSize)) {
                    const char* full_path = (const char*)mods->Module[i].FullPathName;
                    const char* name = full_path;

                    for (int j = 0; full_path[j] != '\0'; j++) {
                        if (full_path[j] == '\\') {
                            name = &full_path[j + 1];
                        }
                    }
                    return name;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return "exception";
        }

        return "not_in_any_module";
    }

    inline PVOID resolve_jmp(PVOID addr) {
        if (!MmIsAddressValid(addr)) return addr;
        UCHAR* b = (UCHAR*)addr;

        /*
        * here we scan the first 15 bytes for jumps. 
        * this is to catch trampolines even if they aren't the very first instruction.
        */


        __try {
            for (int i = 0; i < 15; i++) {
                if (b[i] == 0xE9) {
                    int offset = *(int*)(b + i + 1);
                    return (PVOID)((ULONG_PTR)addr + i + 5 + offset);
                }

                if (b[i] == 0xFF && b[i + 1] == 0x25) {
                    int offset = *(int*)(b + i + 2);
                    /* rip is at the end of instruction */
                    PVOID* target_ptr = (PVOID*)((ULONG_PTR)addr + i + 6 + offset);
                    if (MmIsAddressValid(target_ptr)) {
                        return *target_ptr;
                    }
                }

                if (b[i] == 0x48 && b[i + 1] == 0xB8) {
                    /* check if jmp rax follows the mov */
                    if (b[i + 10] == 0xFF && b[i + 11] == 0xE0) {
                        PVOID target = *(PVOID*)(b + i + 2);
                        return target;
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return addr;
        }
        return addr;
    }

    inline bool validate_handler(PVOID handler, ULONG driver_index, PSYSTEM_MODULE_INFORMATION mods) {
        if (!mods) return false;

        /* resolve any jumps in the first few bytes to get the REAL destination */
        PVOID real_handler = resolve_jmp(handler);

        bool valid = false;
        for (ULONG i = 0; i < mods->Count; i++) {
            /* check if it even lives inside the driver */
            if (addr_in_range(real_handler, mods->Module[i].ImageBase, mods->Module[i].ImageSize)) {

                /* here we verify if its inside .text */
                if (!check_text_section(real_handler, mods->Module[i].ImageBase)) {
                    break;
                }

                /*
                * this logic is a bit meh and can easily be bypassed by using the dkom technique of manually manipulating your index and of course early-boot drivers but requires a cert.
                * however, for this poc it will do, if you are testing your driver against detection do not do this to bypass please :)
                */

                /* if handler is in a different driver */
                if (i != driver_index) {
                    /* allow ntoskrnl (index 0) always */
                    if (i == 0) {
                        valid = true;
                        break;
                    }

                    /* flag suspicious late-load drivers */
                    if (i >= 150) {
                        break; /* not valid */
                    }
                }

                valid = true;
                break;
            }
        }
        return valid;
    }

    inline ULONG get_driver_index(PDRIVER_OBJECT drv, PSYSTEM_MODULE_INFORMATION mods) {
        if (!mods) return 0xFFFFFFFF;
        for (ULONG i = 0; i < mods->Count; i++) {
            if (drv->DriverStart == mods->Module[i].ImageBase) {
                return i;
            }
        }
        return 0xFFFFFFFF;
    }

    inline IRP_SCAN_RESULT scan_driver_irps(PDRIVER_OBJECT driver, PSYSTEM_MODULE_INFORMATION mods) {
        IRP_SCAN_RESULT res = { false, nullptr, driver, "clean" };

        ULONG drv_idx = get_driver_index(driver, mods);

        __try {
            for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
                PVOID handler = driver->MajorFunction[i];
                if (!handler) continue;

                if (!validate_handler(handler, drv_idx, mods)) {
                    res.hooked = true;
                    res.handler = handler;
                    res.info = "hooked irp detected";
                    return res;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            res.hooked = true;
            res.info = "scan exception";
        }

        return res;
    }

    inline ObOpenObjectByName_t get_ob_open_by_name() {
        UNICODE_STRING name = RTL_CONSTANT_STRING(L"ObOpenObjectByName");
        return (ObOpenObjectByName_t)MmGetSystemRoutineAddress(&name);
    }


    inline POBJECT_DIRECTORY get_driver_directory() {
        UNICODE_STRING dir_name = RTL_CONSTANT_STRING(L"\\Driver");

        OBJECT_ATTRIBUTES attr;
        InitializeObjectAttributes(&attr, &dir_name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        HANDLE dir_handle = nullptr;
        auto status = ZwOpenDirectoryObject(&dir_handle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &attr);

        if (!NT_SUCCESS(status)) {
            return nullptr;
        }

        POBJECT_DIRECTORY dir_obj = nullptr;
        status = ObReferenceObjectByHandle(dir_handle, 0, nullptr, KernelMode, (PVOID*)&dir_obj, nullptr);
        ZwClose(dir_handle);

        if (!NT_SUCCESS(status)) {
            return nullptr;
        }

        DbgPrint("[PRIDE] successfully opened driver directory\n"); /* remove this in production, this is just for myself */
        return dir_obj;
    }

    inline void add_driver(driver_list* list, PDRIVER_OBJECT drv) {
        if (list->count >= list->capacity) return;

        for (ULONG i = 0; i < list->count; i++) {
            if (list->drivers[i] == drv) return;
        }

        list->drivers[list->count++] = drv;
    }

    inline driver_list enum_drivers_from_directory() {
        driver_list list = { nullptr, 0, 0 };

        auto dir = get_driver_directory();
        if (!dir) return list;

        list.capacity = 512;
        list.drivers = (PDRIVER_OBJECT*)ExAllocatePoolWithTag(NonPagedPool,
            list.capacity * sizeof(PDRIVER_OBJECT), 'dlst');

        if (!list.drivers) {
            ObDereferenceObject(dir);
            return list;
        }

        __try {
            for (int i = 0; i < 37; i++) {
                auto entry = dir->HashBuckets[i];
                while (entry && MmIsAddressValid(entry)) {
                    if (entry->Object && MmIsAddressValid(entry->Object)) {
                        auto drv = (PDRIVER_OBJECT)entry->Object;
                        if (drv && MmIsAddressValid(drv)) {
                            add_driver(&list, drv);
                        }
                    }
                    entry = entry->ChainLink;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }

        ObDereferenceObject(dir);
        return list;
    }

    inline POBJECT_DIRECTORY get_device_directory() {
        UNICODE_STRING dir_name = RTL_CONSTANT_STRING(L"\\Device");

        OBJECT_ATTRIBUTES attr;
        InitializeObjectAttributes(&attr, &dir_name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        HANDLE dir_handle = nullptr;
        auto status = ZwOpenDirectoryObject(&dir_handle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &attr);

        if (!NT_SUCCESS(status)) {
            return nullptr;
        }

        POBJECT_DIRECTORY dir_obj = nullptr;
        status = ObReferenceObjectByHandle(dir_handle, 0, nullptr, KernelMode, (PVOID*)&dir_obj, nullptr);
        ZwClose(dir_handle);

        if (!NT_SUCCESS(status)) {
            return nullptr;
        }

        DbgPrint("[PRIDE] successfully opened \\Device directory\n"); /* also remove this in production, this is just for myself */
        return dir_obj;
    }

    inline driver_list enum_drivers_from_devices() {
        driver_list list = { nullptr, 0, 0 };

        list.capacity = 2048;
        list.drivers = (PDRIVER_OBJECT*)ExAllocatePoolWithTag(NonPagedPool,
            list.capacity * sizeof(PDRIVER_OBJECT), 'dlst');

        if (!list.drivers) return list;

        auto dir = get_device_directory();
        if (!dir) {
            ExFreePoolWithTag(list.drivers, 'dlst');
            list.drivers = nullptr;
            return list;
        }

        __try {
            for (int i = 0; i < 37; i++) {
                auto entry = dir->HashBuckets[i];
                while (entry && MmIsAddressValid(entry)) {
                    if (entry->Object && MmIsAddressValid(entry->Object)) {

                        /*
                        * here i implement a simple sanity check to make sure we dont accidently resolve something to a device object that isnt
                        * although highly unlikely its best to be safe
                        */

                        auto obj = (PDEVICE_OBJECT)entry->Object;
                        if (obj->Type == IO_TYPE_DEVICE) {
                            if (obj->DriverObject && MmIsAddressValid(obj->DriverObject)) {
                                add_driver(&list, obj->DriverObject);
                            }
                        }
                    }
                    entry = entry->ChainLink;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }

        ObDereferenceObject(dir);
        return list;
    }

    inline bool is_driver_hidden(PDRIVER_OBJECT drv, driver_list* dir_list) {
        for (ULONG i = 0; i < dir_list->count; i++) {
            if (dir_list->drivers[i] == drv) return false;
        }
        return true;
    }

    inline void scan_all_drivers() {
        auto dir_drivers = enum_drivers_from_directory();
        auto dev_drivers = enum_drivers_from_devices();
        auto mods = query_drivers();

        if (!dir_drivers.drivers || !dev_drivers.drivers || !mods) {
            if (dir_drivers.drivers) ExFreePoolWithTag(dir_drivers.drivers, 'dlst');
            if (dev_drivers.drivers) ExFreePoolWithTag(dev_drivers.drivers, 'dlst');
            if (mods) ExFreePoolWithTag(mods, 'prid');
            return;
        }

        DbgPrint("[PRIDE] scanning %lu drivers...\n", dev_drivers.count);

        for (ULONG i = 0; i < dev_drivers.count; i++) {
            auto drv = dev_drivers.drivers[i];
            const char* drv_name = get_driver_name(drv, mods);

            if (is_driver_hidden(drv, &dir_drivers)) {
                DbgPrint("[PRIDE] HIDDEN DRIVER: %s (obj=%p, base=%p)\n",
                    drv_name, drv, drv->DriverStart);
            }

            auto res = scan_driver_irps(drv, mods);
            if (res.hooked) {
                PVOID real_handler = resolve_jmp(res.handler);
                const char* target_module = get_module_name_for_addr(real_handler, mods);

                DbgPrint("[PRIDE] HOOKED IRP: driver=%s handler=%p -> %p (%s) reason=%s\n",
                    drv_name, res.handler, real_handler, target_module, res.info);
            }
        }

        DbgPrint("[PRIDE] scan complete\n");

        ExFreePoolWithTag(dir_drivers.drivers, 'dlst');
        ExFreePoolWithTag(dev_drivers.drivers, 'dlst');
        ExFreePoolWithTag(mods, 'prid');
    }
}