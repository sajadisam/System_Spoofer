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
		if(this)
			GrabValues();
		return this->m_Values;
	}
	
	__forceinline KeysCollection& GetSubKeys() noexcept
	{
		if(this)
			GrabKeys();
		
		return this->m_SubKeys;
	}
	
	__forceinline bool Available() noexcept
	{
		if(this && m_Loaded)
			return true;
		return false;
	}

public:
	RegistryValue* GetValue(const std::string& name) noexcept;
	Registry* GetSubKey(const std::string& name) noexcept;
	bool CreateKey() noexcept;
	bool Rename(const std::string& name) noexcept;
	bool Delete(const std::string& name);
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
	bool m_Loaded;
	bool m_LoadedKeys;
	bool m_LoadedValues;
	HKEY m_Key;
	HKEY m_Folder;
	std::string m_Name;
	std::string m_Path;
	std::string m_RelativePath;
	ValuesCollection m_Values;
	KeysCollection m_SubKeys;
};