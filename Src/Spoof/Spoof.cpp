//
// Created by Xelian on 2021-06-29.
//

#include "Spoof.h"
#include "../Registry/RegistryManager.h"
#include "../Util/Randomizer.h"
#include "../Util/Util.h"
// Computer\HKEY_LOCAL_MACHINE\HARDWARE\DEVICEMAP\VIDEO


/*
 * NIC MAC address.
Your NIC has two types of MAC addresses, permanent and current.

The current mac address can be spoofed easily from usermode by changing the NetworkAddress for the subkeys in

 * Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}
 *(where XXXX is 0000-9999 indicating the subkey representing the nic)
You can also retrieve the current mac address / adapter GUID with GetAdaptersInfo, GetAdaptersAddresses, or through NetBIOS(credits to H4x0rKAPPA for noticing that).
 */

/*
 * Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger
 */

void Spoof::Initialize()
{
	//SpoofDisplay();
	//SpoofEnumAudio();
	//SpoofEnumHID();
	//SpoofGPU();
	//SpoofDrives();
	//SpoofMac();
	//SpoofCPU();
	//SpoofBIOS();
	SpoofWindows();
}

void Spoof::SpoofDisplay()
{
	//SpoofEnumDisplay();
	//auto enumVideo = std::async(std::launch::async, SpoofEnumDisplay);
	//enumVideo.get();
}

void Spoof::SpoofEnumAudio()
{
	Registry* HDAudio = RegistryManager::CreateRegistry(R"(computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\HDAUDIO)");

	const std::string& ClassGUID = "{" + Randomizer::DashedString(7, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS) + "}";
	const std::vector<BYTE>& Security = Randomizer::Binary(70);

	for(const auto& subkey : HDAudio->GetSubKeys())
		for(const auto& subkeyKey : subkey.second->GetSubKeys())
		{
			Registry* subkeyKeyReg = subkeyKey.second.get();
			subkeyKeyReg->GetValue("Security")->Set(Security);
			SpoofEnum(subkeyKeyReg, ClassGUID);
		}
}

void Spoof::SpoofEnumDisplay()
{
	Registry* monitor = RegistryManager::CreateRegistry(R"(computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\DISPLAY)");
	const std::string& ClassGUID = "{" + Randomizer::DashedString(7, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS) + "}";

	for(const auto& key : monitor->GetSubKeys())
	{ //Monitor
		const std::vector<BYTE>& EDID = Randomizer::Binary(128);

		for(const auto& subkey : key.second->GetSubKeys())
		{ //Subkeys inside monitor
			Registry* subkeyReg = subkey.second.get();

			const std::string& HardwareID = "MONITOR\\" + Randomizer::String(4, ALLOW_CAPITALS) + Randomizer::String(3, ALLOW_NUMBERS) + Randomizer::String(1, ALLOW_CAPITALS);
			SpoofEnum(subkeyReg, ClassGUID);
			subkeyReg->GetValue("HardwareID")->Set(HardwareID);
			subkeyReg->GetSubKey("Device Parameters")->GetValue("EDID")->Set(EDID);
			for(auto& propertiesSub : subkeyReg->GetSubKey("Properties")->GetSubKeys())
			{
				const auto& propertiesReg = propertiesSub.second;
				const std::vector<BYTE>& defaultSerial = Randomizer::Binary(8);
				propertiesReg->GetSubKey("0064")->GetValue("")->Set(defaultSerial);
				propertiesReg->GetSubKey("0065")->GetValue("")->Set(defaultSerial);
				propertiesReg->GetSubKey("0066")->GetValue("")->Set(Randomizer::Binary(8));
				propertiesReg->GetSubKey("0067")->GetValue("")->Set(Randomizer::Binary(8));
				propertiesReg->GetSubKey("0002")->GetValue("")->Set(Randomizer::Binary(8));
			}
		}
		spdlog::trace("Finished spoofing: {}", key.first);
	}
}

void Spoof::SpoofEnumHID()
{
	Registry* HID = RegistryManager::CreateRegistry(R"(computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\HID)");
	const std::string& ClassGUID = "{" + Randomizer::DashedString(7, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS) + "}";

	for(const auto& subkey : HID->GetSubKeys())
		for(const auto& subkeyKey : subkey.second->GetSubKeys())
		{
			Registry* subkeyKeyReg = subkeyKey.second.get();
			SpoofEnum(subkeyKeyReg, ClassGUID);
		}

}

void Spoof::SpoofGPU()
{
	Registry* Video = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video)");

	const std::string& UserModeDriverGUID = "{" + Randomizer::DashedString(8, 2, ALLOW_CAPITALS | ALLOW_NUMBERS) + "}";
	for(const auto& subkey : Video->GetSubKeys())
	{
		Registry* videoSubkey = subkey.second->GetSubKey("Video");
		if(!videoSubkey->Available())
			continue;
		else
		{
			const std::string& driverStr = videoSubkey->GetValue("Driver")->Value<std::string>();
			const std::string& Driver = "{" + Randomizer::DashedString(10, 2, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS) + "}" + "\\" + driverStr.substr(driverStr.size() - 4);
			videoSubkey->GetValue("Driver")->Set(Driver);
		}

		for(const auto& subkeyKey : subkey.second->GetSubKeys())
		{
			Registry* subkeyKeyReg = subkeyKey.second.get();
			subkeyKeyReg->GetValue("UserModeDriverGUID")->Set(UserModeDriverGUID);
		}
	}
}

void Spoof::SpoofDrives()
{
	Registry* Scsi = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\HARDWARE\DEVICEMAP\Scsi)");
	for(const auto& ScsiPortKey : Scsi->GetSubKeys())
		for(const auto& ScsiBusKey : ScsiPortKey.second->GetSubKeys())
		{
			Registry* target = ScsiBusKey.second->GetSubKey("Target Id 0");
			if(!target->Available())
				continue;
			for(const auto& units : target->GetSubKeys())
			{
				Registry* unit = units.second.get();
				const std::string& Identifier = Randomizer::String(20, ALLOW_CAPITALS | ALLOW_NUMBERS);
				const std::string& SerialNumber = Randomizer::String(10, ALLOW_CAPITALS | ALLOW_NUMBERS);
				unit->GetValue("Identifier")->Set(Identifier);
				unit->GetValue("SerialNumber")->Set(SerialNumber);
				unit->GetValue("InquiryData")->Set(StringToVector(Identifier));
				unit->GetValue("DeviceIdentifierPage")->Set(Randomizer::Binary(15));
			}
		}
}

void Spoof::SpoofMac()
{
	Registry* mac = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318})");
	if(!mac->Available())
	{
		std::cout << "Couldn't find mac address registry" << "\n";
		return;
	}
	for(const auto& subkey : mac->GetSubKeys())
	{
		const auto networkAddress = subkey.second->GetValue("NetworkAddress");
		if(networkAddress)
		{
			constexpr char acceptedStr[] = "26AE";  /* Mac address doesn't accept other than these letters */
			std::string data;
			data.resize(12);
			for(int i = 0; i < 12; ++i)
				data[i] = acceptedStr[Randomizer::Integer(0, 3)];
			networkAddress->Set(data);
			std::cout << "Spoofed network: " << subkey.second->GetValue("DriverDesc")->Value<std::string>() << "\n";
		}
	}

}

void Spoof::SpoofCPU()
{

}

void Spoof::SpoofBIOS()
{
	/* HKEY_LOCAL_MACHINE\SYSTEM\HardwareConfig\{04a0a952-0cd9-11eb-b8c1-682be17c1907} */
	Registry* bios = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS");
	const std::string& BaseBoardProduct = bios->GetValue("BaseBoardProduct")->Value<std::string>();
	const std::string& BaseBoardProductName = BaseBoardProduct.substr(0, BaseBoardProduct.find('('));

	const std::string& SystemProductName = "MS-" + Randomizer::String(4, ALLOW_NUMBERS | ALLOW_CAPITALS);
	const std::string& BIOSVersion = std::to_string(Randomizer::Integer(1, 9)) + "." + std::to_string(Randomizer::Integer(1, 99));
	const std::string& SystemVersion = std::to_string(Randomizer::Integer(1, 9)) + "." + std::to_string(Randomizer::Integer(1, 99));
	const std::string& BaseBoardProductMODIFIED = BaseBoardProductName + "(" + SystemProductName + ")";
	const std::string& BaseBoardManufacturer = Randomizer::String(7, ALLOW_CAPITALS | ALLOW_NUMBERS);

	bios->GetValue("BIOSVersion")->Set(BIOSVersion);
	bios->GetValue("SystemVersion")->Set(SystemVersion);
	bios->GetValue("SystemProductName")->Set(SystemProductName);
	bios->GetValue("BaseBoardProduct")->Set(BaseBoardProductMODIFIED);
	bios->GetValue("BaseBoardManufacturer")->Set(BaseBoardManufacturer);

	Registry* bios2 = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\HardwareConfig\\{04a0a952-0cd9-11eb-b8c1-682be17c1907}");
	bios2->GetValue("BIOSVersion")->Set(BIOSVersion);
	bios2->GetValue("SystemVersion")->Set(SystemVersion);
	bios2->GetValue("SystemProductName")->Set(SystemProductName);
	bios2->GetValue("BaseBoardProduct")->Set(BaseBoardProductMODIFIED);
	bios2->GetValue("BaseBoardManufacturer")->Set(BaseBoardManufacturer);
}

void Spoof::SpoofEnum(Registry* registry, const std::string& randomClassGUID)
{
	const std::string& ContainerID = "{" + Randomizer::DashedString(7, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS) + "}";
	const std::string& driverStr = registry->GetValue("Driver")->Value<std::string>();
	const std::string& Driver = randomClassGUID + "\\" + driverStr.substr(driverStr.size() - 4);

	const std::string& prevHardwareID = registry->GetValue("HardwareID")->Value<std::string>();
	const std::string& HardwareID = prevHardwareID.substr(0, prevHardwareID.find('\\') + 1) + Randomizer::String(20, ALLOW_NUMBERS | ALLOW_CAPITALS);

	registry->GetValue("HardwareID")->Set(HardwareID);
	registry->GetValue("Driver")->Set(Driver);
	registry->GetValue("ClassGUID")->Set(randomClassGUID);
	registry->GetValue("ContainerID")->Set(ContainerID);
}

void Spoof::SpoofWindows()
{
	Registry* windows = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
	windows->GetValue("DigitalProductId")->Set(Randomizer::Binary(0xA0 * 2));
	windows->GetValue("DigitalProductId4")->Set(Randomizer::Binary(0x4F8 * 2));
	windows->GetValue("InstallDate")->Set(Randomizer::Integer(1623000000, 1623001747));
	windows->GetValue("ProductId")->Set(Randomizer::DashedString(5, 3, ALLOW_NUMBERS | ALLOW_CAPITALS));
	windows->GetValue("UBR")->Set(Randomizer::Integer(1000, 1099));
}