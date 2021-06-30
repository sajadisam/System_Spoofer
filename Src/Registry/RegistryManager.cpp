//
// Created by Xelian on 2021-06-24.
//
#include "RegistryManager.h"
static std::string ReadFile(const std::string& name)
{
	std::ifstream f(name);
	if(!f.good())
		return "";
	std::string buffer;
	std::stringstream ss;
	while(std::getline(f, buffer))
		ss << buffer << "\n";
	f.close();
	return ss.str();
}

std::vector<std::shared_ptr<Registry>> RegistryManager::m_Registries;
Registry* RegistryManager::CreateRegistry(const std::string& path)
{
	m_Registries.emplace_back(std::make_shared<Registry>(path));
	return m_Registries.back().get();
}
bool RegistryManager::SaveValues()
{
	std::ifstream f("Save.json");
	if(f.good())
	{
		f.close();
		return false;
	}
	std::ofstream file("Save.json");
	nlohmann::json js;

	for(const auto& registry : m_Registries)
		js += registry->m_Save;

	file << js.dump(1);
	file.close();
	f.close();
	return true;
}
bool RegistryManager::ResetValues()
{
	std::string file = ReadFile("Save.json");
	if(file.empty())
		return false;
	nlohmann::json js = nlohmann::json::parse(file);
	for(const auto& item : js)
	{
		const std::string& folder = item["Folder"];
		const std::string& path = item["Path"];
		for(const auto& val : item["Values"])
		{
			const std::string& value_name = val["Name"];
			const int& type_id = val["Type"];
			switch(type_id)
			{
			case REG_SZ:
			case REG_EXPAND_SZ:
			case REG_MULTI_SZ:
				CreateRegistry(path)->GetValue(value_name)->Set(val["Value"].get<std::string>());
				break;
			case REG_BINARY:
				CreateRegistry(path)
					->GetValue(value_name)
					->Set(val["Value"].get<std::vector<int>>());
				break;
			case REG_DWORD:
				CreateRegistry(path)->GetValue(value_name)->Set(val["Value"].get<int>());
				break;
			}
		}
	}
	return true;
}
