//
// Created by Xelian on 2021-06-18.
//

#include "RegistryValue.h"

#define REG_DEFAULT 0xffff0010
// TODO: Proper exception handling when setting registry values

RegistryValue::RegistryValue(
		HKEY& key, const std::string& name, DWORD type, nlohmann::json& saves) : m_Key(key), m_Name(name), m_Type(type), m_Saves(saves)
{
}

DWORD RegistryValue::GetBufferSize(const std::string& name)
{
	DWORD size = 0;
	CheckKeyValue(RegQueryValueEx(m_Key, m_Name.c_str(), NULL, NULL, NULL, &size));
	return size;
}

void RegistryValue::CheckKeyValue(LRESULT error)
{
	if(error != ERROR_SUCCESS)
	{
		const std::string& field = "Field \"" + m_Name + "\": ";
		switch(error)
		{
			case ERROR_FILE_NOT_FOUND:
				throw std::runtime_error(field + "was not found");
			case ERROR_MORE_DATA:
				throw std::runtime_error(field + "requires more data in the buffer");
			default:
				throw std::runtime_error(field + "unknown error");
		}
	}
}

std::string RegistryValue::ReadString()
{
	if(m_Type != REG_SZ && m_Type != REG_EXPAND_SZ && m_Type != REG_MULTI_SZ)
		throw std::runtime_error("You're reading invalid type");
	std::string buff;
	DWORD size = GetBufferSize(m_Name);
	buff.resize(size - 1);
	CheckKeyValue(RegQueryValueEx(m_Key, m_Name.c_str(), NULL, &m_Type, (LPBYTE)&buff[0], &size));
	return buff;
}

std::vector<BYTE> RegistryValue::ReadBinaryAsByte()
{
	std::vector<BYTE> buffer;
	DWORD size = GetBufferSize(m_Name.c_str());
	buffer.resize(size);
	CheckKeyValue(RegQueryValueEx(m_Key, m_Name.c_str(), NULL, &m_Type, (LPBYTE)&buffer[0], &size));
	return buffer;
}

std::vector<int> RegistryValue::ReadBinaryAsInt()
{
	std::vector<BYTE> data = ReadBinaryAsByte();
	return std::vector<int>(data.begin(), data.end());
}

void RegistryValue::Delete()
{
#if ENABLE_DELETE
	if(this)
		CheckKeyValue(RegDeleteValueA(m_Key, m_Name.c_str()));
#endif
}

void RegistryValue::Set(int type, void* buffer, int size)
{
#if ENABLE_SET
	if(!this)
		return;
	LSTATUS error = RegSetValueExA(m_Key, m_Name.c_str(), NULL, type, (BYTE*)buffer, size);
	if(m_Type == REG_NONE || error != ERROR_SUCCESS)
	{
		EMBER_WARN("Failed to set: {0}", m_Name);
		return;
	}
	m_Value["Name"] = m_Name;
	m_Value["Type"] = (int)m_Type;
	m_Saves["Values"] += m_Value;
#endif
}

void RegistryValue::Set(std::string str)
{
#if ENABLE_SET
	if(!this)
		return;
	
	switch(m_Type)
	{
		case REG_NONE:
		case REG_SZ:
		case REG_EXPAND_SZ:
		case REG_MULTI_SZ:
			if(m_Type != REG_NONE)
				m_Value["Value"] += Value<std::string>();
			Set(m_Type, &str[0], str.size());
			break;
		default:
			return;
	}
#endif
}

void RegistryValue::Set(const std::vector<int>& binary)
{
#if ENABLE_SET
	if(!this)
		return;
	if(m_Type != REG_BINARY && m_Type != REG_NONE)
		return;
	m_Value["Value"] += Value<std::vector<int>>();
	std::vector<BYTE> buffer(binary.begin(), binary.end());
	Set(REG_BINARY, (void*)&buffer[0], buffer.size());
#endif
}

void RegistryValue::Set(const std::vector<BYTE>& binary)
{
#if ENABLE_SET
	if(!this)
		return;
	if(m_Type != REG_BINARY && m_Type != REG_NONE && m_Type != REG_DEFAULT)
		return;
	m_Value["Value"] += Value<std::vector<int>>();
	Set(REG_BINARY, (void*)&binary[0], binary.size());
#endif
}

void RegistryValue::Set(int number)
{
#if ENABLE_SET
	if(!this)
		return;
	
	if(m_Type != REG_DWORD && m_Type != REG_NONE)
		return;
	m_Value["Value"] += Value<int>();
	Set(m_Type, (void*)(DWORD*)&number, sizeof(DWORD));
#endif
}