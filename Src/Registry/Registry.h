//
// Created by Xelian on 2021-06-18.
//
#pragma once

#include "RegistryValue.h"

class Registry
{
public:
	using ValuesCollection = std::unordered_map<std::string, std::shared_ptr<RegistryValue>>;
	using KeysCollection = std::map<std::string, std::shared_ptr<Registry>>;

public:
	Registry(const std::string& path);
	Registry() = delete;
	Registry(Registry&&) = delete;
	~Registry();

public:
	__forceinline ValuesCollection& GetValues() noexcept
	{
		if(Available())
			GrabValues();
		return this->m_Values;
	}
	
	__forceinline KeysCollection& GetSubKeys() noexcept
	{
		if(Available())
			GrabKeys();
		return this->m_SubKeys;
	}
	
	__forceinline bool Available() noexcept
	{
		return (this && m_Loaded);
	}

public:
	RegistryValue* GetValue(const std::string& name) noexcept;
	Registry* GetSubKey(const std::string& name) noexcept;
	bool CreateKey() noexcept;
	bool Rename(const std::string& name) noexcept;
	bool Delete(const std::string& name) noexcept;
	RegistryValue* CreateValue(const std::string& name) noexcept;
	nlohmann::json m_Save;
private:
	void GrabValues() noexcept;
	void GrabKeys() noexcept;
	void Open();
	HKEY SetFolder() noexcept;
	std::string FormatPath() noexcept;
	void TakeOwnership();

private:
	bool m_Loaded = false;
	bool m_LoadedKeys = false;
	bool m_LoadedValues = false;
	HKEY m_Key = 0;
	HKEY m_Folder = 0;
	std::string m_Name = "";
	std::string m_Path = "";
	std::string m_RelativePath = "";
	std::string  m_StringFolder = "";
	ValuesCollection m_Values = ValuesCollection();
	KeysCollection m_SubKeys = KeysCollection();
};