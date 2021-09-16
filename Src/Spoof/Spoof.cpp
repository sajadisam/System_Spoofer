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

static struct ClassSession
{
	ClassSession()
	{
		m_RmRCPrevDriverBranch = Randomizer::Binary(30);
		m_RmRCPrevDriverChangelist = Randomizer::Binary(20);
		m_RmRCPrevDriverLoadCount = Randomizer::Binary(10);
		m_RmRCPrevDriverVersion = Randomizer::Binary(30);
		m_vbios = Randomizer::Binary(500);
	}
	
	void Spoof(Registry* sessionRegistry)
	{
		sessionRegistry->GetValue("RmRCPrevDriverBranch")->Set(m_RmRCPrevDriverBranch);
		sessionRegistry->GetValue("RmRCPrevDriverChangelist")->Set(m_RmRCPrevDriverChangelist);
		sessionRegistry->GetValue("RmRCPrevDriverLoadCount")->Set(m_RmRCPrevDriverLoadCount);
		sessionRegistry->GetValue("RmRCPrevDriverVersion")->Set(m_RmRCPrevDriverVersion);
		sessionRegistry->GetValue("vbios")->Set(m_vbios);
	}

private:
	bool init = false;
	std::vector<BYTE> m_RmRCPrevDriverBranch;
	std::vector<BYTE> m_RmRCPrevDriverChangelist;
	std::vector<BYTE> m_RmRCPrevDriverLoadCount;
	std::vector<BYTE> m_RmRCPrevDriverVersion;
	std::vector<BYTE> m_vbios;
} s_GPUSession;

static void SpoofEnum(Registry* registry, const std::string& randomClassGUID)
{
	//const std::string& ContainerID = "{" + Randomizer::DashedString(7, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS) + "}";
	//const std::string& driverStr = registry->GetValue("Driver")->Value<std::string>();
	//const std::string& Driver = randomClassGUID + "\\" + driverStr.substr(driverStr.size() - 4);
	
	const std::string& prevHardwareID = registry->GetValue("HardwareID")->Value<std::string>();
	const std::string& HardwareID = prevHardwareID.substr(0, prevHardwareID.find('\\') + 1) + Randomizer::String(20, ALLOW_NUMBERS | ALLOW_CAPITALS);
	
	registry->GetValue("HardwareID")->Set(HardwareID);
	//registry->GetValue("Driver")->Set(Driver); //Cause to failure of boot
	//registry->GetValue("ClassGUID")->Set(randomClassGUID);//Cause to failure of boot
	//registry->GetValue("ContainerID")->Set(ContainerID);//Cause to failure of boot
}


void Spoof::Initialize()
{
	EMBER_INFO("Initializing Spoofer...");
	SpoofCPU();
	EMBER_INFO("SpoofCPU");
	SpoofGPU();
	EMBER_INFO("SpoofGPU");
	SpoofMisc();
	EMBER_INFO("SpoofMisc");
	SpoofDrives();
	EMBER_INFO("SpoofDrives");
	SpoofMac();
	EMBER_INFO("SpoofMac");
	SpoofBIOS();
	EMBER_INFO("SpoofBIOS");
	SpoofWindows();
	EMBER_INFO("SpoofWindows");
	SpoofDisplay();
	EMBER_INFO("SpoofDisplay");
	SpoofEnumAudio();
	EMBER_INFO("SpoofEnumAudio");
	SpoofEnumHID();
	EMBER_INFO("SpoofEnumHID");
	SpoofEnumPCI();
	EMBER_INFO("SpoofEnumPCI");
	SpoofRust();
	EMBER_INFO("SpoofRust");
	
	EMBER_INFO("=========FINISHED SPOOFING REGISTRY=========");
	
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

void Spoof::SpoofDisplay()
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
	
	Registry* devicesClassesDisplay = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\DeviceClasses\{10910c20-0c64-4172-9409-add3064c0cad})");
	for(const auto& subkey : devicesClassesDisplay->GetSubKeys())
	{
		subkey.second->GetValue("")->Set(Randomizer::String(32, ALLOW_NONE_CAPITALS | ALLOW_NONE_CAPITALS | ALLOW_NUMBERS));
	}
	Registry* BasicDisplay = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicDisplay)");
	std::string videoId = "{" + Randomizer::DashedString(8, 4, ALLOW_CAPITALS | ALLOW_NUMBERS) + "}";
	BasicDisplay->GetSubKey("Video")->GetValue("VideoID")->Set(videoId);
	for(const auto& subKey : BasicDisplay->GetSubKey("VolatileSettings")->GetValues())
	{
		if(subKey.second->GetType() == REG_BINARY)
			subKey.second->Set(Randomizer::Binary(0x80 * 2));
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
	Registry* video = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video)");
	const std::string& UserModeDriverGUID = "{" + Randomizer::DashedString(8, 2, ALLOW_CAPITALS | ALLOW_NUMBERS) + "}";
	const auto& volatileSettings = Randomizer::Binary(300);
	for(const auto& subkey : video->GetSubKeys())
	{
		Registry* videoSubkey = subkey.second->GetSubKey("video");
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
			subkeyKeyReg->GetValue("DriverDateData")->Set(Randomizer::Binary(50));
			subkeyKeyReg->GetValue("ModePersistence")->Set(Randomizer::Binary(500));
			
			s_GPUSession.Spoof(subkeyKeyReg->GetSubKey("Session"));
			subkeyKeyReg->GetSubKey("VolatileSettings")->GetValue("{5b45201d-f2f2-4f3b-85bb-30ff1f953599}")->Set(volatileSettings);
		}
	}
	
	Registry* video2 = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class)");
	for(const auto& subkey : video2->GetSubKeys())
	{
		Registry* vidSubkey = subkey.second->GetSubKey("0000");
		if(!vidSubkey->GetSubKey("VolatileSettings")->Available())
			continue;
		
		vidSubkey->GetValue("UserModeDriverGUID")->Set(UserModeDriverGUID);
		vidSubkey->GetValue("DriverDateData")->Set(Randomizer::Binary(50));
		vidSubkey->GetValue("ModePersistence")->Set(Randomizer::Binary(500));
		s_GPUSession.Spoof(vidSubkey->GetSubKey("Session"));
		for(const auto& subValue : vidSubkey->GetSubKey("VolatileSettings")->GetValues())
		{
			if(subValue.second->GetType() == REG_BINARY)
				subValue.second->Set(volatileSettings);
		}
	}
	
	Registry* video3 = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Video)");
	for(const auto& subkey : video3->GetSubKeys())
	{
		if(!subkey.second->GetSubKey("Video")->Available())
			continue;
		
		for(const auto& subsubkey : subkey.second->GetSubKeys())
		{
			if(subsubkey.first == "Video")
				continue;
			subsubkey.second->GetValue("UserModeDriverGUID")->Set(UserModeDriverGUID);
			subsubkey.second->GetValue("DriverDateData")->Set(Randomizer::Binary(50));
			subsubkey.second->GetValue("ModePersistence")->Set(Randomizer::Binary(500));
			s_GPUSession.Spoof(subsubkey.second->GetSubKey("Session"));
			subsubkey.second->GetSubKey("VolatileSettings")->GetValue("{5b45201d-f2f2-4f3b-85bb-30ff1f953599}")->Set(volatileSettings);
			
		}
	}
	Registry* video4 = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318})");
	for(const auto& subkey : video4->GetSubKeys())
	{
		if(subkey.first == "Configuration" || subkey.first == "Properties")
			continue;
		Registry* subregistry = subkey.second.get();
		subregistry->GetValue("DriverDate")->Set(Randomizer::Date());
		subregistry->GetValue("DriverDateData")->Set(Randomizer::Binary(0x8 * 2));
		subregistry->GetValue("UserModeDriverGUID")->Set("{" + Randomizer::DashedString(8, 4, ALLOW_CAPITALS | ALLOW_NUMBERS) + "}");
		s_GPUSession.Spoof(subregistry->GetSubKey("Session"));
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
	
	Registry* disk = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\MultifunctionAdapter\0\DiskController\0\DiskPeripheral)");
	for(const auto& subkey: disk->GetSubKeys())
	{
		const std::string& Identifier = Randomizer::DashedString(8, 1, ALLOW_NUMBERS | ALLOW_NONE_CAPITALS) + "-A";
		subkey.second->GetValue("Identifier")->Set(Identifier);
	}
	
	Registry* ControlDisk = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318})");
	for(const auto& subkey : ControlDisk->GetSubKeys())
	{
		if(subkey.first == "Configuration" || subkey.first == "Properties")
			continue;
		subkey.second->GetValue("DriverDateData")->Set(Randomizer::Binary(0x8 * 2));
		subkey.second->GetValue("DriverVersion")->Set(Randomizer::String(2, ALLOW_NUMBERS) + "." + Randomizer::String(5, ALLOW_NUMBERS) + Randomizer::String(3, ALLOW_NUMBERS));
	}
	
}

bool Spoof::SpoofMac()
{
	Registry* mac = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318})");
	if(!mac->Available())
		return false;
	
	int NetLuidIndex = Randomizer::Integer(30000, 40000);
	for(const auto& subkey : mac->GetSubKeys())
	{
		subkey.second->GetValue("InstallTimeStamp")->Set(Randomizer::Binary(32));
		subkey.second->GetValue("NetworkInterfaceInstallTimestamp")->Set(Randomizer::Integer(1000000000, 2000000000));
		subkey.second->GetValue("NetLuidIndex")->Set(NetLuidIndex);
		const auto PnPCapabilities = subkey.second->GetValue("PnPCapabilities");
		if(PnPCapabilities) //Checks active network cards
		{
			constexpr char acceptedStr[] = "26AE";  /* Mac address doesn't accept other than these letters */
			std::string data;
			data.resize(12);
			for(int i = 0; i < 12; ++i)
				data[i] = acceptedStr[Randomizer::Integer(0, 3)];
			
			const auto networkAddress = subkey.second->GetValue("NetworkAddress");
			if(!networkAddress)
				subkey.second->CreateValue("NetworkAddress")->Set(data);
			else
				networkAddress->Set(data);
		}
	}
	return true;
	
}

void Spoof::SpoofCPU()
{
	std::string subkeyNameForCPU = "";
	Registry* acpi = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\ACPI)");
	const std::string& ClassGUID = "{" + Randomizer::DashedString(7, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS) + "}";
	for(const auto& subkey : acpi->GetSubKeys())
	{
		if(subkey.first.size() > 25)
		{
			subkeyNameForCPU = subkey.first;
			continue;
		}
		for(const auto& subsubkey : acpi->GetSubKeys())
			SpoofEnum(subsubkey.second.get(), ClassGUID);
		
	}
	const std::string& ClassGUID2 = "{" + Randomizer::DashedString(7, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS) + "}";
	if(!subkeyNameForCPU.empty())
	{
		const std::string& cpuFriendlyName = Randomizer::String(25, ALLOW_NUMBERS | ALLOW_CAPITALS | ALLOW_NONE_CAPITALS);
		Registry* cpuACPI = acpi->GetSubKey(subkeyNameForCPU);
		for(const auto& subkey : cpuACPI->GetSubKeys())
		{
			SpoofEnum(subkey.second.get(), ClassGUID2);
			subkey.second->GetValue("FriendlyName")->Set(cpuFriendlyName);
		}
	} else
		EMBER_ERROR("Couldn't find CPU subkey!");
	Registry* descriptionSystem = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\)");
	struct CPU_INFO
	{
		std::string name = Randomizer::String(20, ALLOW_CAPITALS | ALLOW_NUMBERS | ALLOW_NONE_CAPITALS);
		std::string identifer = Randomizer::String(30, ALLOW_CAPITALS | ALLOW_NUMBERS | ALLOW_NONE_CAPITALS);
		int FeatureSet = Randomizer::Integer(1000000000, 1500000000);
		int Platform_Specific_Field1 = Randomizer::Integer(1000000000, 1500000000);
		std::vector<BYTE> revision = Randomizer::Binary(0x8 * 2);
	} cpuInfo;
	
	for(const auto& subkey : descriptionSystem->GetSubKey("CentralProcessor")->GetSubKeys())
	{
		Registry* key = subkey.second.get();
		key->GetValue("FeatureSet")->Set(cpuInfo.FeatureSet);
		key->GetValue("Platform Specific Field1")->Set(cpuInfo.Platform_Specific_Field1);
		key->GetValue("Previous Update Revision")->Set(cpuInfo.revision);
		key->GetValue("Update Revision")->Set(cpuInfo.revision);
		key->GetValue("ProcessorNameString")->Set(cpuInfo.name);
		key->GetValue("Identifier")->Set(cpuInfo.identifer);
	}
	for(const auto& subkey : descriptionSystem->GetSubKey("FloatingPointProcessor")->GetSubKeys())
		subkey.second->GetValue("Identifier")->Set(cpuInfo.identifer);
	
}

void Spoof::SpoofBIOS()
{
	Registry* bios = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS)");
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
	
	Registry* bios2 = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\HardwareConfig)");
	for(const auto& subkey: bios2->GetSubKeys())
	{
		subkey.second->GetValue("BIOSVersion")->Set(BIOSVersion);
		subkey.second->GetValue("SystemVersion")->Set(SystemVersion);
		subkey.second->GetValue("SystemProductName")->Set(SystemProductName);
		subkey.second->GetValue("BaseBoardProduct")->Set(BaseBoardProductMODIFIED);
		subkey.second->GetValue("BaseBoardManufacturer")->Set(BaseBoardManufacturer);
		
		// WARNING: potentially dangerous!
		for(const auto& computerID : subkey.second->GetSubKey("ComputerIds")->GetValues())
			computerID.second->Delete();
		for(const auto& productId : subkey.second->GetSubKey("ProductIds")->GetValues())
			productId.second->Delete();
	}
	
	Registry* bios3 = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemInformation)");
	const std::string& ComputerHardwareId = "{" + Randomizer::DashedString(8, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS) + "}";
	bios3->GetValue("BIOSVersion")->Set(BIOSVersion);
	bios3->GetValue("SystemProductName")->Set(SystemProductName);
	bios3->GetValue("ComputerHardwareId")->Set(ComputerHardwareId);
	bios3->GetValue("ComputerHardwareIds")->Set(ComputerHardwareId);
	
	Registry* deviceClassesCPU = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\DeviceClasses\{97fadb10-4e33-40ae-359c-8bef029dbdd0})");
	for(const auto& subKey : deviceClassesCPU->GetSubKeys())
		subKey.second->GetValue("DeviceInstance")->Set("ACPI\\" + Randomizer::String(60, ALLOW_CAPITALS | ALLOW_NONE_CAPITALS | ALLOW_NUMBERS));
}

void Spoof::SpoofMisc()
{
	const std::string& serialFolder = GetSerialFolder();
	
	Registry* mssmbios = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mssmbios\Data)");
	for(const auto& getValue : mssmbios->GetValues())
		getValue.second->Set(Randomizer::Binary(400 * 2));
	
	Registry* mountedDevices = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices)");
	for(const auto& getValue : mountedDevices->GetValues())
		getValue.second->Set(Randomizer::Binary(400 * 4));
	
	Registry* hardwareConfig = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\HardwareConfig)");
	const std::string& LastConfig = "{" + Randomizer::DashedString(6, 4) + "}";
	const std::string& oldLastConfig = hardwareConfig->GetValue("LastConfig")->Value<std::string>();
	
	RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Dfrg)")->Delete("Statistics");
	
	Registry* WindowsAIKHash = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TPM\WMI)");
	WindowsAIKHash->GetValue("WindowsAIKHash")->Set(Randomizer::Binary(500));
	RegistryManager::CreateRegistry(R"(Computer\HKEY_CURRENT_USER\Software\Microsoft\Direct3D)")->GetValue("WHQLClass")->Set(Randomizer::Binary(500));
	RegistryManager::CreateRegistry(R"(Computer\HKEY_CURRENT_USER\Software\Classes\Installer\Dependencies)")->GetValue("MSICache")->Set(Randomizer::Binary(500));
	RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TPM\ODUID)")->GetValue("RandomSeed")->Set(Randomizer::Binary(500));
	
	const std::string& MachineGuid = Randomizer::DashedString(7, 4, ALLOW_NUMBERS | ALLOW_NONE_CAPITALS);
	RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography)")->GetValue("MachineGuid")->Set(MachineGuid);
	
	const std::string& HwProfileGuid = "{" + Randomizer::DashedString(8, 3, ALLOW_NUMBERS | ALLOW_NONE_CAPITALS) + "}";
	RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001)")->GetValue("HwProfileGuid")->Set(HwProfileGuid);
	
	const std::string& SusClientId = Randomizer::DashedString(8, 4, ALLOW_NUMBERS | ALLOW_NONE_CAPITALS);
	
	RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters)")->GetValue("Dhcpv6DUID")->Set(Randomizer::Binary(50));
	
	RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Migration)")->GetValue("IE Installed Date")->Set(Randomizer::Binary(30));
	Registry* SQMClient = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient)");
	SQMClient->GetValue("MachineId")->Set(Randomizer::DashedString(10, 3, ALLOW_CAPITALS | ALLOW_NUMBERS));
	SQMClient->GetValue("WinSqmFirstSessionStartTime")->Set(Randomizer::Integer(1000000000, 2000000000));
	
	Registry* DiagTrack = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack)");
	DiagTrack->GetSubKey("EventTranscriptKey")->GetValue("LastCommittedPrivacyNamespaceETag")->Set("\"" + Randomizer::String(16, ALLOW_CAPITALS | ALLOW_NUMBERS) + "\"");
	DiagTrack->GetSubKey("SevilleEventlogManager")->GetValue("LastEventlogWrittenTime")->Set(Randomizer::Integer(1000000000, 2000000000));
	Registry* SettingsRequests = DiagTrack->GetSubKey("SettingsRequests");
	for(const auto& subkey : SettingsRequests->GetSubKeys())
		SettingsRequests->Delete(subkey.first);
	
	Registry* MuiCache = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\" + serialFolder + "_Classes" + "\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache");
	for(const auto& subvalue : MuiCache->GetValues())
		if(subvalue.first != "LangID")
			subvalue.second->Delete();
	
	Registry* MuiCache2 = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\" + serialFolder + "\\SOFTWARE\\Classes\\Local "
	                                                                                                "Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache");
	for(const auto& subvalue : MuiCache2->GetValues())
		if(subvalue.first != "LangID")
			subvalue.second->Delete();
	
	Registry* s1 = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\" + serialFolder);
	Registry* s1Software = s1->GetSubKey("SOFTWARE");
	s1Software->Delete("Hex-Rays");
	s1Software->Delete("Sysinternals");
	s1Software->Delete("WindowPop");
	s1Software->Delete("VMware, Inc.");
	s1Software->Delete("Epic Games");
	
	Registry* DirectInput = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\" + serialFolder + "\\System\\CurrentControlSet\\Control"
	                                                                                                  "\\MediaProperties\\PrivateProperties\\DirectInput");
	for(const auto& subkey : DirectInput->GetSubKeys())
	{
		Registry* Calibration = subkey.second->GetSubKey("Calibration");
		for(const auto& calibrationSubkey : Calibration->GetSubKeys())
			calibrationSubkey.second->GetValue("GUID")->Set(Randomizer::Binary(32));
	}
	
	
	Registry* GameConfigStore = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\" + serialFolder + "\\System\\GameConfigStore");
	for(const auto& child : GameConfigStore->GetSubKey("Children")->GetSubKeys())
		child.second->GetValue("GameDVR_GameGUID")->Set(Randomizer::DashedString(8, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS));
	
	Registry* ControlSubkey = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\{7746D80F-97E0-4E26-9543-26B41FC22F79})");
	for(const auto& subvalue : ControlSubkey->GetValues())
		if(subvalue.second->GetType() == REG_BINARY)
			subvalue.second->Set(Randomizer::Binary(0x20 * 2));
	
	
	//WARN: This is potentially dangerous!
	Registry* usersetting = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings)");
	for(const auto& subkey : usersetting->GetSubKeys())
	{
		if(subkey.first.size() < 25)
		{
			for(const auto& subvalue : subkey.second->GetValues())
			{
				if(subvalue.second->GetType() == REG_BINARY)
					subvalue.second->Set(Randomizer::Binary(0x18 * 2));
			}
		}
	}
	
	//WARN: This is potentially dangerous!
	Registry* userSerialFolder = usersetting->GetSubKey(serialFolder);
	for(const auto& subvalue : userSerialFolder->GetValues())
	{
		if(subvalue.first[0] != '\\')
		{
			subvalue.second->Set(Randomizer::Binary(0x18 * 2));
			continue;
		}
		subvalue.second->Delete();
	}
	//WARN: This is potentially dangerous!
	Registry* userSerialFolder2 = usersetting->GetSubKey(serialFolder.substr(0, serialFolder.size() - 1) + "0");
	for(const auto& subvalue : userSerialFolder2->GetValues())
		if(subvalue.second->GetType() == REG_BINARY)
			subvalue.second->Set(Randomizer::Binary(0x18 * 2));
	
		Registry* Autologger = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger");
	for(const auto& subKey : Autologger->GetSubKeys())
	{
		std::string guid = "{" + Randomizer::DashedString(8,4,ALLOW_CAPITALS | ALLOW_NUMBERS) + "}";
		subKey.second->GetValue("Guid")->Set(guid);
	}
}

void Spoof::SpoofWindows()
{
	Registry* windows = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion)");
	windows->GetValue("DigitalProductId")->Set(Randomizer::Binary(0xA0 * 2));
	windows->GetValue("DigitalProductId4")->Set(Randomizer::Binary(0x4F8 * 2));
	windows->GetValue("InstallDate")->Set(Randomizer::Integer(1623000000, 1623001747));
	windows->GetValue("ProductId")->Set(Randomizer::DashedString(5, 3, ALLOW_NUMBERS | ALLOW_CAPITALS));
	windows->GetValue("UBR")->Set(Randomizer::Integer(1000, 1099));
	windows->GetValue("InstallTime")->Set(Randomizer::Integer(1000000000, 2000000000));
	
	Registry* windows2 = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform)");
	windows2->GetValue("BackupProductKeyDefault")->Set(Randomizer::DashedString(5, 4, ALLOW_CAPITALS | ALLOW_NUMBERS));
	windows2->GetValue("actionlist")->Set(Randomizer::Binary(50));
	windows2->GetValue("LicStatusArray")->Set(Randomizer::Binary(300));
	windows2->GetValue("PolicyValuesArray")->Set(Randomizer::Binary(300));
	windows2->GetValue("ServiceSessionId")->Set(Randomizer::Binary(100));
	windows2->GetSubKey("Activation")->GetValue("ProductActivationTime")->Set(Randomizer::Integer(1000000000, 2000000000));
	
	Registry* explorer = RegistryManager::CreateRegistry(R"(Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer)");
	Registry* exprUserAssist = explorer->GetSubKey("UserAssist");
	for(const auto& item : exprUserAssist->GetSubKeys())
		exprUserAssist->Delete(item.first);
	Registry* bitbucket = explorer->GetSubKey("BitBucket");
	bitbucket->GetValue("LastEnum")->Delete();
	bitbucket->Delete("Volume");
	const auto& cpcVolumes = explorer->GetSubKey("MountPoints2")->GetSubKey("CPC")->GetSubKey("Volume");
	const auto& volumeData = Randomizer::Binary(500 * 2);
	for(const auto& volume : cpcVolumes->GetSubKeys())
		volume.second->GetValue("Data")->Set(volumeData);
	
	Registry* WindowsUpdate = RegistryManager::CreateRegistry(R"(Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate)");
	WindowsUpdate->GetValue("SusClientIdValidation")->Set(Randomizer::Binary(200));
	for(const auto& value: WindowsUpdate->GetValues())
	{
		std::string id = value.first.substr(value.first.size() - 2);
		std::transform(id.begin(), id.end(), id.begin(), [](char c) {
			return std::tolower(c);
		});
		if(id == "id" && value.second->GetType() == REG_SZ)
		{
			const std::string& uniqueID = Randomizer::DashedString(8, 4, ALLOW_NUMBERS | ALLOW_NONE_CAPITALS);
			value.second->Set(uniqueID);
		}
	}
}

void Spoof::SpoofEnumPCI()
{
	Registry* pci = RegistryManager::CreateRegistry(R"(computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\DISPLAY)");
	const std::string& ClassGUID = "{" + Randomizer::DashedString(7, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS) + "}";
	
	for(const auto& key: pci->GetSubKeys())
		for(const auto& subkey : key.second->GetSubKeys())
			SpoofEnum(subkey.second.get(), ClassGUID);
}

void Spoof::SpoofRust()
{
	const std::string& rustSteamAppId = "252490";
	Registry* software = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\" + GetSerialFolder() + "\\SOFTWARE");
	software->Delete("Facepunch Studios LTD");
	
	Registry* unistall = RegistryManager::CreateRegistry(R"(HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall)");
	unistall->Delete("Steam App" + rustSteamAppId);
	
	Registry* GameConfigStore = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\" + GetSerialFolder() + "\\System\\GameConfigStore");
	for(const auto& child : GameConfigStore->GetSubKey("Children")->GetSubKeys())
	{
		RegistryValue* MatchedExeFullPath = child.second->GetValue("MatchedExeFullPath");
		if(MatchedExeFullPath)
		{
			const std::string& fullString = MatchedExeFullPath->Value<std::string>();
			const int& position = fullString.find_last_of('\\');
			if(position != std::string::npos)
				if(fullString.substr(position + 1) == "RustClient.exe")
					GameConfigStore->Delete(child.first);
		}
	}
	Registry* SteamAppRust = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\" + GetSerialFolder() + "\\SOFTWARE\\Valve\\Steam\\Apps");
	SteamAppRust->Delete(rustSteamAppId);
	Registry* FacePunchSoftware = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\" + GetSerialFolder() + "\\SOFTWARE");
	FacePunchSoftware->Delete("Facepunch Studios LTD");
}

std::string Spoof::GetSerialFolder()
{
	static std::string cached = "";
	if(!cached.empty())
		return cached;
	
	Registry* serialRegistry = RegistryManager::CreateRegistry(R"(Computer\HKEY_USERS)");
	for(const auto& subkey : serialRegistry->GetSubKeys())
		if(subkey.first.find("S-1-5-21") != std::string::npos)
		{
			cached = subkey.first;
			cached[cached.size() - 1] = '1';
			return cached;
		}
	
	return cached;
	
}