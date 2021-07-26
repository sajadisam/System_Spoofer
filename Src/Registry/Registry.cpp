//
// Created by Xelian on 2021-06-18.
//

#include "Registry.h"
#include "../Util/Util.h"
#include <winreg.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "err_typecheck_invalid_operands"

static bool SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if(!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
		throw std::runtime_error("LookupPrivilegeValue error");
	
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if(bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	
	if(!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
		throw std::runtime_error("AdjustTokenPrivileges error");
	
	if(GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		throw std::runtime_error("The token does not have the specified privilege");
	
	return true;
}

Registry::Registry(const std::string& path) : m_Path(path), m_Loaded(false), m_LoadedKeys(false), m_LoadedValues(false)
{
	try
	{
		if(m_Path.empty())
			throw std::runtime_error("Path is empty");
		m_RelativePath = FormatPath();
		m_Folder = SetFolder();
		if(!m_Folder)
			throw std::runtime_error("Path \"" + m_Path + "\" is incorrect");
		Open();
	} catch(const std::exception& e)
	{
		EMBER_ERROR("{0}", e.what());
		return;
	}
	m_Loaded = true;
}

Registry::~Registry()
{
	if(m_Loaded)
		RegCloseKey(m_Key);
}

void Registry::Open()
{
	if(!this)
		return;
	LSTATUS openResult = RegOpenKeyEx(m_Folder, m_RelativePath.c_str(), 0, KEY_ALL_ACCESS, &m_Key);
	if(openResult == ERROR_ACCESS_DENIED)
	{
		TakeOwnership();
		openResult = RegOpenKeyEx(m_Folder, m_RelativePath.c_str(), 0, KEY_ALL_ACCESS, &m_Key);
	}
	if(openResult == ERROR_FILE_NOT_FOUND)
		openResult = RegOpenKeyEx(m_Folder, m_RelativePath.c_str(), 0, KEY_WOW64_64KEY | KEY_ALL_ACCESS, &m_Key);
	
	if(openResult != ERROR_SUCCESS)
	{
		switch(openResult)
		{
			case ERROR_FILE_NOT_FOUND:
				throw std::runtime_error("Key not found: " + m_Path);
			case ERROR_ACCESS_DENIED:
				throw std::runtime_error("ACCESS_DENIED for key: " + m_Path);
			default:
				throw std::runtime_error("Failed opening key: " + m_Path + " ERROR: " + std::to_string(openResult) + ". " + m_RelativePath);
		}
	}
}

std::string Registry::FormatPath() noexcept
{
	if(m_Path.empty())
		return "";
	
	int index = 0;
	for(int i = 0; i < m_Path.size(); ++i)
	{
		if(m_Path[i] == '\\')
		{
			if(++index == 2)
			{
				return m_Path.substr(i + 1);
			}
		}
	}
	return "";
}

HKEY Registry::SetFolder() noexcept
{
	if(m_Path.empty())
		return NULL;
	
	std::vector<std::string> segmentations = SegmentPhrase(m_Path, '\\');
	m_StringFolder = segmentations[1];
	m_Save["Path"] = m_Path;
	m_Save["Folder"] = m_StringFolder;
	if(m_Path.back() == '\\')
		m_Name = segmentations[segmentations.size() - 2];
	else
		m_Name = segmentations.back();
	
	if(m_StringFolder == "HKEY_CLASSES_ROOT")
		return HKEY_CLASSES_ROOT;
	if(m_StringFolder == "HKEY_CURRENT_USER")
		return HKEY_CURRENT_USER;
	if(m_StringFolder == "HKEY_LOCAL_MACHINE")
		return HKEY_LOCAL_MACHINE;
	if(m_StringFolder == "HKEY_USERS")
		return HKEY_USERS;
	if(m_StringFolder == "HKEY_CURRENT_CONFIG")
		return HKEY_CURRENT_CONFIG;
	return NULL;
}

void Registry::GrabValues() noexcept
{
	if(m_LoadedValues)
		return;
	
	if(!Available())
		return;
	int error;
	int index = 0;
	do
	{
		char nameBuffer[255] = "";
		DWORD nameBufferSize = 255;
		DWORD type = 0;
		error = RegEnumValueA(m_Key, index++, nameBuffer, &nameBufferSize, NULL, &type, NULL, NULL);
		if(error == ERROR_SUCCESS)
			m_Values.insert({nameBuffer, std::make_shared<RegistryValue>(m_Key, nameBuffer, type, m_Save)});
		else if(error != ERROR_SUCCESS && error != ERROR_NO_MORE_ITEMS)
		{
			EMBER_ERROR("{0}", error);
			return;
		}
	} while(error != ERROR_NO_MORE_ITEMS);
	m_LoadedValues = true;
}

void Registry::GrabKeys() noexcept
{
	if(!Available())
		return;
	int error;
	int index = 0;
	do
	{
		char nameBuffer[255] = "";
		DWORD nameBufferSize = 255;
		error = RegEnumKeyA(m_Key, index++, nameBuffer, nameBufferSize);
		if(error == ERROR_SUCCESS)
			m_SubKeys.insert({nameBuffer, std::make_shared<Registry>(m_Path + "\\" + nameBuffer)});
	} while(error != ERROR_NO_MORE_ITEMS && error != ERROR_INVALID_HANDLE);
	m_LoadedKeys = true;
}

Registry* Registry::GetSubKey(const std::string& name) noexcept
{
	if(!Available())
		return nullptr;
	if(!m_LoadedKeys)
		GrabKeys();
	auto it = m_SubKeys.find(name);
	if(it != m_SubKeys.end())
		return it->second.get();
	
	return nullptr;
}

RegistryValue* Registry::GetValue(const std::string& name) noexcept
{
	if(!Available())
		return nullptr;
	
	if(!m_LoadedValues)
		GrabValues();
	
	auto it = m_Values.find(name);
	if(it != m_Values.end())
		return it->second.get();
	return nullptr;
}

bool Registry::CreateKey() noexcept
{
	if(Available())
		return false;
	LSTATUS error = RegCreateKeyA(m_Folder, m_RelativePath.c_str(), &m_Key);
	if(error != ERROR_SUCCESS)
		return false;
	m_SubKeys.insert({m_Name, std::make_shared<Registry>(m_RelativePath.c_str())});
	return true;
}

bool Registry::Rename(const std::string& name) noexcept
{
#if ENABLE_SET
	if(!Available())
		return false;
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	const std::wstring& wOldName = converter.from_bytes(m_RelativePath);
	const std::wstring& wNewName = converter.from_bytes(name);
	LSTATUS error = RegRenameKey(m_Folder, wOldName.c_str(), wNewName.c_str());
	if(error != ERROR_SUCCESS)
		return false;
	return true;
#else
	return false;
#endif
}

RegistryValue* Registry::CreateValue(const std::string& name) noexcept
{
#if ENABLE_SET
	LSTATUS error = RegSetValueExA(m_Key, name.c_str(), 0, 0, nullptr, 0);
	if(error != ERROR_SUCCESS)
		return nullptr;
	m_Values.insert({name, std::make_shared<RegistryValue>(m_Key, name, REG_NONE, m_Save)});
	return m_Values[name].get();
#else
	return nullptr;
#endif
}


void Registry::TakeOwnership()
{
	if(!this)
		return;
	
	HANDLE hToken = NULL;
	PSID pSIDAdmin = NULL;
	PSID pSIDEveryone = NULL;
	PACL pACL = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	constexpr int NUM_ACES = 2;
	EXPLICIT_ACCESS ea[NUM_ACES];
	DWORD dwRes;
	try
	{
		if(!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pSIDEveryone))
			throw std::runtime_error("AllocateAndInitializeSid (Everyone) error");
		
		if(!AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSIDAdmin))
			throw std::runtime_error("AllocateAndInitializeSid (Admin) error");
		
		ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));
		ea[0].grfAccessPermissions = GENERIC_READ;
		ea[0].grfAccessMode = SET_ACCESS;
		ea[0].grfInheritance = NO_INHERITANCE;
		ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
		ea[0].Trustee.ptstrName = (LPTSTR)pSIDEveryone;
		
		ea[1].grfAccessPermissions = GENERIC_ALL;
		ea[1].grfAccessMode = SET_ACCESS;
		ea[1].grfInheritance = NO_INHERITANCE;
		ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
		ea[1].Trustee.ptstrName = (LPTSTR)pSIDAdmin;
		
		if(ERROR_SUCCESS != SetEntriesInAcl(NUM_ACES, ea, NULL, &pACL))
			throw std::runtime_error("Failed SetEntriesInAcl");
		
		std::string folder;
		if(m_Folder == HKEY_CLASSES_ROOT)
			folder = "CLASSES_ROOT";
		else if(m_Folder == HKEY_CURRENT_CONFIG)
			folder = "CURRENT_CONFIG";
		else if(m_Folder == HKEY_CURRENT_USER)
			folder = "CURRENT_USER";
		else if(m_Folder == HKEY_LOCAL_MACHINE)
			folder = "MACHINE";
		else if(m_Folder == HKEY_USERS)
			folder = "USERS";
		const std::string& path = folder + "\\" + m_RelativePath;
		char* str = const_cast<char*>(path.c_str());
		
		if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
			throw std::runtime_error("Failed to open process token");
		
		if(!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, TRUE))
			throw std::runtime_error("User must be logged on as Administrator");
		
		dwRes = SetNamedSecurityInfo(str, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, pSIDAdmin, NULL, NULL, NULL);
		if(dwRes != ERROR_SUCCESS)
			throw std::runtime_error("Could not set owner");
		
		if(!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, FALSE))
			throw std::runtime_error("Failed SetPrivilege call unexpectedly");
		
		dwRes = SetNamedSecurityInfo(str, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pACL, NULL);
		
		if(dwRes != ERROR_SUCCESS)
			throw std::runtime_error("Failed setting DACL after taking ownership");
	} catch(const std::exception& e)
	{
		std::cout << "[SETTING PERMISSION]" << e.what() << std::endl;
	}
	if(pSIDAdmin)
		FreeSid(pSIDAdmin);
	if(pSIDEveryone)
		FreeSid(pSIDEveryone);
	if(pACL)
		LocalFree(pACL);
	if(hToken)
		CloseHandle(hToken);
}

bool Registry::Delete(const std::string& name) noexcept
{
#if ENABLE_DELETE
	if(!this && !m_Loaded)
		return false;
	
	Registry temp(m_Path + "\\" + name);
	if(!temp.m_Loaded)
		return false;
	const auto& keys = temp.GetSubKeys();
	for(const auto& key : keys)
		temp.Delete(key.first);
	
	LSTATUS result = RegDeleteKeyA(m_Key, name.c_str());
	if(result != ERROR_SUCCESS)
		return false;
	
	return true;
#else
	return false;
#endif
	
}


#pragma clang diagnostic pop