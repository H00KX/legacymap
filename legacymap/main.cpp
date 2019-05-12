#include <iostream>
#include <cstdio>
#include <fstream>
#include <Windows.h>
#include <winternl.h>
#include <string>
#include "capcom.hpp"
#include "capcomsys.hpp"
#include "util.hpp"
#include "drv_image.hpp"
#include <cassert>
#include "structs.hpp"

struct IUnknown; // Workaround for combaseapi.h(229): error C2187

//Links against ntdll for RtlInitUnicodeString implementation
#pragma comment(lib, "ntdll.lib")

// Actual low level driver loading functions
extern "C" NTSTATUS NTAPI ZwLoadDriver(PUNICODE_STRING str);
extern "C" NTSTATUS NTAPI ZwUnloadDriver(PUNICODE_STRING str);

inline LSTATUS prepare_reg(const wchar_t *svcName, const wchar_t *svcDrv, const wchar_t *group, int startupType)
{
	HKEY key;
	HKEY subkey;

	DWORD type = 1;
	DWORD err = 0;
	LSTATUS status = 0;

	// Path to load/store the registry key
	wchar_t path[MAX_PATH];
	swprintf(path, ARRAYSIZE(path), L"\\??\\%s", svcDrv);

	// Check if the Capcom service is already registered.
	status = RegOpenKeyW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services", &key);
	if (status)
	{
		printf("[+] The capcom service was already registered.\n");
		return status;
	}

	// Create the Capcom service.
	status = RegCreateKeyW(key, svcName, &subkey);
	if (status)
	{
		RegCloseKey(key);
		printf("Registered capcom service successfully.\n");
		return status;
	}

	status |= RegSetValueExW(subkey, L"DisplayName", 0, REG_SZ, (const BYTE *)svcName, (DWORD)(sizeof(WCHAR) * wcslen(svcName) + 1));
	status |= RegSetValueExW(subkey, L"ErrorControl", 0, REG_DWORD, (const BYTE *)&err, sizeof(err));
	status |= RegSetValueExW(subkey, L"Group", 0, REG_SZ, (const BYTE *)group, sizeof(WCHAR) * ((DWORD)wcslen(group) + 1));
	status |= RegSetValueExW(subkey, L"ImagePath", 0, REG_SZ, (const BYTE *)path, (sizeof(WCHAR) * ((DWORD)wcslen(path) + 1)));
	status |= RegSetValueExW(subkey, L"Start", 0, REG_DWORD, (const BYTE *)&startupType, sizeof(startupType));
	status |= RegSetValueExW(subkey, L"Type", 0, REG_DWORD, (const BYTE*)&type, sizeof(type));

	RegCloseKey(subkey);
	if(status != ERROR_SUCCESS)
	{
		printf("[+] Failed to register the capcom service.\n");
	}else
	{
		printf("[+] Created and registered the capcom service.\n");
	}

	return status;
}

// Create a path for the capcom driver service
inline std::wstring make_path(const std::wstring& svcName)
{
	std::wstring path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services";
	path += L"\\" + svcName;
	return path;
}

inline bool set_privilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	// Local user id?
	LUID luid;

	// If the privilege the caller is trying to change doesn't exist, return false;
	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		return false;
	}

	// Create a privilege to apply
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		tp.Privileges[0].Attributes = 0;
	}

	// Attempt to apply the privilage to the token (calling application), return false on failure.
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		return false;
	}

	// Make SURE the assignment succeeded.
	return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

inline bool load_driver(const std::wstring& path, const std::wstring& service)
{
	// Prepare registry key(s) for driver
	LSTATUS status = prepare_reg(service.c_str(), path.c_str(), L"Base", 1);

	// Return if unsuccessful
	if (status != ERROR_SUCCESS)
	{
		return status;
	}

	// Make a path for the driver
	UNICODE_STRING str;
	auto wpath = make_path(service);
	RtlInitUnicodeString(&str, wpath.c_str());

	printf("Service Path: ");
	std::wcout << wpath;
	printf("\n");

	// Attempt to get the "adjust-privileges" token for this process. If it doesn't have admin rights then this fails.
	HANDLE token;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
	{
		printf("[+] Couldn't get the privilege adjustment token for this process.\n");
		return false;
	}

	// Attempt to give this application the privilage to load drivers
	const auto done = set_privilege(token, TEXT("SeLoadDriverPrivilege"), TRUE);
	CloseHandle(token);
	if (!done)
	{
		printf("[+] Couldn't give this process the privilege to load drivers.\n");
		return false;
	}
	printf("[+] Driver loading privilege granted for this process.\n");

	const auto ld = ZwLoadDriver(&str);
	if(ld == 0)
	{
		printf("[+] ZwLoadDriver succeeded.\n");
	}
	else
	{
		printf("[+] ZwLoadDriver failed. %I32X\n", ld);
	}

	return ld == 0;
}

inline bool unload_driver(const std::wstring& service)
{
	HKEY key;
	UNICODE_STRING str;
	auto wservice = make_path(service);
	RtlInitUnicodeString(&str, wservice.c_str());

	// Attempt to get the "adjust-privileges" token for this process. If it doesn't have admin rights then this fails.
	HANDLE token;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
	{
		printf("[+] Couldn't get the privilege adjustment token for this process.\n");
		return false;
	}

	// Attempt to give this application the privilage to load/unload drivers
	const auto done = set_privilege(token, TEXT("SeLoadDriverPrivilege"), TRUE);
	CloseHandle(token);
	if (!done)
	{
		printf("[+] Couldn't give this process the privilege to unload drivers.\n");
		return false;
	}
	printf("[+] Driver unloading privilege granted for this process.\n");

	auto ld = ZwUnloadDriver(&str);
	if (ld != 0)
	{
		printf("[+] ZwUnloadDriver failed. %I32X\n", ld);
		return false;
	}
	else
	{
		printf("[+] ZwUnloadDriver successful.\n");
	}

	// Clean the registry entry
	const auto rk = RegOpenKeyW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services", &key);

	if (rk == ERROR_SUCCESS)
	{
		printf("[+] Found the capcom driver to remove in registry.\n");
		const auto rd = RegDeleteKeyW(key, L"Capcom");

		if(rd == ERROR_SUCCESS)
		{
			printf("[+] Deleted the capcom key.\n");
		} else
		{
			printf("[+] Failed to delete the capcom key. %I32X\n", rd);
			return false;
		}

		const auto rc = RegCloseKey(key);
		if (rc == ERROR_SUCCESS)
		{
			printf("[+] Closed the key.\n");
		} else
		{
			printf("[+] Failed to close the key.\n");
			return false;
		}
	} else
	{
		printf("[+] Capcom registry key wasn't found at\n\t");
		std::wcout << wservice;
		printf("[|] Error code: %I32X\n", rk);
		return false;
	}

	return true;
}

// Capcom driver loading routine
inline bool load_capcom(uint8_t* driver, int size, const std::wstring& path, const std::wstring& service)
{
	std::ofstream file(path.c_str(), std::ios_base::out | std::ios_base::binary);
	file.write((char*)driver, size);
	file.close();
	printf("[+] Wrote out capcom.sys to %ls\n", path.c_str());
	return load_driver(path, service);
}

// Capcom driver unload routine
inline bool unload_capcom(const std::wstring& path, const std::wstring& service)
{
	if (!unload_driver(service))
	{
		return false;
	}

	return std::remove(std::string(path.begin(), path.end()).c_str());
}

int __stdcall main(const int argc, char** argv)
{
	// Attempt to load the capcom driver from C:\Windows\Capcom.sys
	printf("[+] Starting...\n");
	unload_capcom(L"C:\\Windows\\Capcom.sys", L"Capcom");
	bool capcomload = load_capcom((uint8_t*)capcom_sys, sizeof(capcom_sys), L"C:\\Windows\\Capcom.sys", L"Capcom");
	if (capcomload)
	{
		printf("[+] Loaded the capcom driver.\n");
	}
	else
	{
		printf("[+] Failed to load the capcom driver.\n");
		//return EXIT_FAILURE;
	}

	// Create an instance of the capcom driver object from capcom.cpp
	const auto capcom = std::make_unique<capcom::capcom_driver>();
	printf("[+] Created an instance of the capcom driver object.\n");

	const auto _get_module = [&capcom](std::string_view name)
	{
		printf("[+] Getting kernel module %.*s\n", static_cast<int>(name.size()), name.data());

		return capcom->get_kernel_module(name);
	};

	const auto _get_export_name = [&capcom](uintptr_t base, const char* name)
	{
		printf("[+] Getting export %s by name for the user driver object.\n", name);
		return capcom->get_export(base, name);
	};

	const std::function<uintptr_t(uintptr_t, uint16_t)> _get_export_ordinal = [&capcom](uintptr_t base, uint16_t ord)
	{
		printf("[+] Getting export %i by ordinal for the user driver object.\n", ord);
		return capcom->get_export(base, ord);
	};

	// Load the user driver image
	//sizeof(SYSTEM_INFORMATION_CLASS::SystemBasicInformation);
	std::vector<uint8_t> driver_image;
	open_binary_file(argv[1], driver_image);

	if(driver_image.empty())
	{
		printf("[+] Failed to read the driver image.");
		return EXIT_FAILURE;
	}

	drv_image driver(driver_image);
	printf("[+] Created an instance of the user driver image.\n");

	// Allocate the capcom driver some kernel memory in a nonpaged pool.
	const auto capcom_pool_base = capcom->allocate_pool(driver.size(), kernel::NonPagedPool, true);
	if(capcom_pool_base == 0)
	{
		printf("[+] Failed to allocate a pool for the Capcom process.\n");
		return EXIT_FAILURE;
	}

	printf("[+] Allocated 0x%llu bytes for driver in Capcom pool at 0x%I64X\n", driver.size(), capcom_pool_base);
	
	// Fix imports of the user driver for when it is in kernel memory
	driver.fix_imports(_get_module, _get_export_name, _get_export_ordinal);
	printf("[+] User driver imports fixed.\n");
	
	// Map the user driver into kernel memory.
	driver.map();
	printf("[+] User driver mapped to general memory.\n");

	// Adjust memory relocations defined in the user driver, to match its future location in memory.
	driver.relocate(capcom_pool_base);
	printf("[+] Fixed relocations....?\n");
	
	const auto _RtlCopyMemory = capcom->get_system_routine<structs::RtlCopyMemoryFn>(L"RtlCopyMemory");

	const auto size = driver.size();
	const auto source = driver.data();
	const auto entry_point = capcom_pool_base + driver.entry_point();

	printf("[+] Future address of user driver entry point: 0x%p\n", (void*)entry_point);

	printf("[+] Attempting to copy user driver into Capcom's pool.\n");

	// Copy the user driver into the capcom pool.
	capcom->run([&capcom_pool_base, &source, &size, &_RtlCopyMemory](auto get_mm)
	{
		_RtlCopyMemory((void*)capcom_pool_base, source, size);
	});

	NTSTATUS status = STATUS_FAILED_DRIVER_ENTRY;
	const auto capcom_base = capcom->get_kernel_module("Capcom");
	printf("[+] Base of capcom module: 0x%p\n", (void*)capcom_base);
	
	// Execute/start the user driver driver_entry function.
	printf("[+] Calling entry point of user driver at 0x%p\n", (void*)entry_point);

	capcom->run([&entry_point, &status, &capcom_pool_base, &capcom_base](auto mm_get)
	{
		status = ((structs::PDRIVER_INITIALIZE)entry_point)((structs::_DRIVER_OBJECT*)capcom_base, (PUNICODE_STRING)capcom_pool_base);
	});
	
	if(NT_SUCCESS(status))
	{
		printf("[+] Successfully intialized the user driver from Capcom's pool.\n");

		const auto _RtlZeroMemory = capcom->get_system_routine<structs::RtlZeroMemoryFn>(L"RtlZeroMemory");
		const auto header_size = driver.header_size();

		capcom->run([&_RtlZeroMemory, &capcom_pool_base, &header_size](auto mm_get)
		{
			_RtlZeroMemory((void*)capcom_pool_base, header_size);
		});

		printf("[+] Wiped headers from user driver.\n");
	}
	else
	{
		printf("[+] Failed to initialize the user driver object. 0x%I32X\n", status);
	}

	capcom->close_driver_handle();
	capcomload = unload_capcom(L"C:\\Windows\\Capcom.sys", L"Capcom");
	printf("[+] Unloaded the Capcom driver.\n");


	while (1) {}
	return EXIT_SUCCESS;
}