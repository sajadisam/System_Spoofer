//
// Created by Xelian on 2021-06-29.
//

#include "Spoof.h"
#include "../Registry/RegistryManager.h"
#include "../Util/Randomizer.h"

void Spoof::SpoofMonitor() {
	const std::string& MonitorName = Randomizer::String(3, ALLOW_CAPITALS) +
									 Randomizer::String(4, ALLOW_CAPITALS | ALLOW_NUMBERS);
	const std::string& ClassGUID =
		Randomizer::DashedString(5, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS);
	const std::string& ContainerID =
		Randomizer::DashedString(5, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS);
	const std::string& MonitorDriverSerial = "{" + ClassGUID + "}\\0004";
	const std::string& HardwareID = "MONITOR\\" + MonitorName;
	const std::string& SubKeyName = std::to_string(Randomizer::Integer(0, 9)) + "&" +
									Randomizer::String(7, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS) +
									"&0&UID0";


	Registry* monitor = RegistryManager::CreateRegistry(
		"computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY");

	for(auto& key : monitor->GetSubKeys())
	{
		if (key.first == "Default_Monitor")
			continue;
		std::cout << key.first << "\n";
	}
}
