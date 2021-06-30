//
// Created by Xelian on 2021-06-24.
//

#pragma once
#include "Registry.h"

class RegistryManager
{
public:
	RegistryManager() = delete;
	~RegistryManager() = delete;

public:
	static Registry* CreateRegistry(const std::string& path);
	static bool SaveValues();
	static bool ResetValues();
private:
	static std::vector<std::shared_ptr<Registry>> m_Registries;
};
