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


// TODO: CPU spoofing

struct ClassSession
{
	ClassSession()
	{
		m_RmRCPrevDriverBranch = Randomizer::Binary(30);
		m_RmRCPrevDriverChangelist = Randomizer::Binary(20);
		m_RmRCPrevDriverLoadCount = Randomizer::Binary(10);
		m_RmRCPrevDriverVersion = Randomizer::Binary(30);
		m_vbios = Randomizer::Binary(500);
	}
	
	void Spoof(Registry* registry)
	{
		registry->GetValue("RmRCPrevDriverBranch")->Set(m_RmRCPrevDriverBranch);
		registry->GetValue("RmRCPrevDriverChangelist")->Set(m_RmRCPrevDriverChangelist);
		registry->GetValue("RmRCPrevDriverLoadCount")->Set(m_RmRCPrevDriverLoadCount);
		registry->GetValue("RmRCPrevDriverVersion")->Set(m_RmRCPrevDriverVersion);
		registry->GetValue("vbios")->Set(m_vbios);
	}

private:
	bool init = false;
	std::vector<BYTE> m_RmRCPrevDriverBranch;
	std::vector<BYTE> m_RmRCPrevDriverChangelist;
	std::vector<BYTE> m_RmRCPrevDriverLoadCount;
	std::vector<BYTE> m_RmRCPrevDriverVersion;
	std::vector<BYTE> m_vbios;
};

static void SpoofEnum(Registry* registry, const std::string& randomClassGUID)
{
	const std::string& ContainerID = "{" + Randomizer::DashedString(7, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS) + "}";
	const std::string& driverStr = registry->GetValue("Driver")->Value<std::string>();
	const std::string& Driver = randomClassGUID + "\\" + driverStr.substr(driverStr.size() - 4);
	
	const std::string& prevHardwareID = registry->GetValue("HardwareID")->Value<std::string>();
	const std::string& HardwareID = prevHardwareID.substr(0, prevHardwareID.find('\\') + 1) + Randomizer::String(20, ALLOW_NUMBERS | ALLOW_CAPITALS);
	
	registry->GetValue("HardwareID")->Set(HardwareID);
	//registry->GetValue("Driver")->Set(Driver); //Cause to failure of boot
	//registry->GetValue("ClassGUID")->Set(randomClassGUID);//Cause to failure of boot
	//registry->GetValue("ContainerID")->Set(ContainerID);//Cause to failure of boot
}


void Spoof::Initialize()
{
	SpoofCPU(); // TODO: Finish spoofing cpu
	std::cout << "SpoofCPU" << "\n";
	SpoofGPU();
	std::cout << "SpoofGPU" << "\n";
	SpoofMisc();
	std::cout << "SpoofMisc" << "\n";
	SpoofDrives();
	std::cout << "SpoofDrives" << "\n";
	SpoofMac();
	std::cout << "SpoofMac" << "\n";
	SpoofBIOS();
	std::cout << "SpoofBIOS" << "\n";
	SpoofWindows();
	std::cout << "SpoofWindows" << "\n";
	SpoofEnumDisplay();
	std::cout << "SpoofEnumDisplay" << "\n";
	SpoofEnumAudio();
	std::cout << "SpoofEnumAudio" << "\n";
	SpoofEnumHID();
	std::cout << "SpoofEnumHID" << "\n";
	SpoofEnumPCI();
	std::cout << "SpoofEnumPCI" << "\n";
	
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
	//TODO: Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicDisplay
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
	ClassSession session;
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
			
			session.Spoof(subkeyKeyReg->GetSubKey("Session"));
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
		session.Spoof(vidSubkey->GetSubKey("Session"));
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
			session.Spoof(subsubkey.second->GetSubKey("Session"));
			subsubkey.second->GetSubKey("VolatileSettings")->GetValue("{5b45201d-f2f2-4f3b-85bb-30ff1f953599}")->Set(volatileSettings);
			
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
	
	Registry* disk = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral");
	for(const auto& subkey: disk->GetSubKeys())
	{
		const std::string& Identifier = Randomizer::DashedString(8, 1, ALLOW_NUMBERS | ALLOW_NONE_CAPITALS) + "-A";
		subkey.second->GetValue("Identifier")->Set(Identifier);
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

}

void Spoof::SpoofBIOS()
{
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
	
	Registry* bios2 = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\HardwareConfig");
	for(const auto& subkey: bios2->GetSubKeys())
	{
		if(subkey.first == "Current")
			continue;
		subkey.second->GetValue("BIOSVersion")->Set(BIOSVersion);
		subkey.second->GetValue("SystemVersion")->Set(SystemVersion);
		subkey.second->GetValue("SystemProductName")->Set(SystemProductName);
		subkey.second->GetValue("BaseBoardProduct")->Set(BaseBoardProductMODIFIED);
		subkey.second->GetValue("BaseBoardManufacturer")->Set(BaseBoardManufacturer);
	}
	
	Registry* bios3 = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation");
	const std::string& ComputerHardwareId = Randomizer::DashedString(8, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS);
	bios3->GetValue("BIOSVersion")->Set(BIOSVersion);
	bios3->GetValue("SystemProductName")->Set(SystemProductName);
	bios3->GetValue("ComputerHardwareId")->Set(ComputerHardwareId);
	//bios3->GetValue("ComputerHardwareIds")->Set(); //TODO: Finish this one
	
}

void Spoof::SpoofMisc()
{
	Registry* mssmbios = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data");
	for(const auto& getValue : mssmbios->GetValues())
		getValue.second->Set(Randomizer::Binary(400 * 2));
	
	Registry* mountedDevices = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\MountedDevices");
	for(const auto& getValue : mountedDevices->GetValues())
		getValue.second->Set(Randomizer::Binary(400 * 4));
	
	Registry* hardwareConfig = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\HardwareConfig");
	const std::string& LastConfig = "{" + Randomizer::DashedString(6, 4) + "}";
	const std::string& oldLastConfig = hardwareConfig->GetValue("LastConfig")->Value<std::string>();
	
	RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Dfrg")->Delete("Statistics");
	
	Registry* WindowsAIKHash = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI");
	WindowsAIKHash->GetValue("WindowsAIKHash")->Set(Randomizer::Binary(500));
	RegistryManager::CreateRegistry("Computer\\HKEY_CURRENT_USER\\s1Software\\Microsoft\\Direct3D")->GetValue("WHQLClass")->Set(Randomizer::Binary(500));
	RegistryManager::CreateRegistry("Computer\\HKEY_CURRENT_USER\\s1Software\\Classes\\Installer\\Dependencies")->GetValue("MSICache")->Set(Randomizer::Binary(500));
	RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID")->GetValue("RandomSeed")->Set(Randomizer::Binary(500));
	
	const std::string& MachineGuid = Randomizer::DashedString(7, 4, ALLOW_NUMBERS | ALLOW_NONE_CAPITALS);
	RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography")->GetValue("MachineGuid")->Set(MachineGuid);
	
	const std::string& HwProfileGuid = "{" + Randomizer::DashedString(8, 3, ALLOW_NUMBERS | ALLOW_NONE_CAPITALS) + "}";
	RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001")->GetValue("HwProfileGuid")->Set(HwProfileGuid);
	
	const std::string& SusClientId = Randomizer::DashedString(8, 4, ALLOW_NUMBERS | ALLOW_NONE_CAPITALS);
	
	RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters")->GetValue("Dhcpv6DUID")->Set(Randomizer::Binary(50));
	
	RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Internet Explorer\\Migration")->GetValue("IE Installed Date")->Set(Randomizer::Binary(30));
	Registry* SQMClient = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SQMClient");
	SQMClient->GetValue("MachineId")->Set(Randomizer::DashedString(10, 3, ALLOW_CAPITALS | ALLOW_NUMBERS));
	SQMClient->GetValue("WinSqmFirstSessionStartTime")->Set(Randomizer::Integer(1000000000, 2000000000));
	
	Registry* DiagTrack = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack");
	DiagTrack->GetSubKey("EventTranscriptKey")->GetValue("LastCommittedPrivacyNamespaceETag")->Set("\"" + Randomizer::String(16, ALLOW_CAPITALS | ALLOW_NUMBERS) + "\"");
	DiagTrack->GetSubKey("SevilleEventlogManager")->GetValue("LastEventlogWrittenTime")->Set(Randomizer::Integer(1000000000, 2000000000));
	Registry* SettingsRequests = DiagTrack->GetSubKey("SettingsRequests");
	for(const auto& subkey : SettingsRequests->GetSubKeys())
		SettingsRequests->Delete(subkey.first);
	
	Registry* MuiCache = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\S-1-5-21-2416424366-1165671203-1984061266-1001_Classes\\Local Settings\\s1Software\\Microsoft\\Windows\\Shell\\MuiCache");
	for(const auto& subvalue : MuiCache->GetValues())
		if(subvalue.first != "LangID")
			subvalue.second->Delete();
	
	Registry* s1 = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\S-1-5-21-2416424366-1165671203-1984061266-1001");
	Registry* s1Software = s1->GetSubKey("SOFTWARE");
	s1Software->Delete("Hex-Rays");
	s1Software->Delete("Sysinternals");
	s1Software->Delete("WindowPop");
	s1Software->Delete("VMware, Inc.");
	s1Software->Delete("Epic Games");
	
	Registry* DirectInput = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\S-1-5-21-2416424366-1165671203-1984061266-1001\\System\\CurrentControlSet\\Control"
	                                                        "\\MediaProperties\\PrivateProperties\\DirectInput");
	for(const auto& subkey : DirectInput->GetSubKeys())
	{
		Registry* Calibration = subkey.second->GetSubKey("Calibration");
		for(const auto& calibrationSubkey : Calibration->GetSubKeys())
			calibrationSubkey.second->GetValue("GUID")->Set(Randomizer::Binary(32));
	}
	Registry* usersetting = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-2416424366-1165671203"
	                                                        "-1984061266-1001");
	for(const auto& subvalue : usersetting->GetValues())
	{
		if(subvalue.first == "Version" || subvalue.first == "SequenceNumber" || subvalue.first.substr(subvalue.first.size() - 4) != ".exe")
			continue;
		subvalue.second->Delete();
	}
	
	Registry* GameConfigStore = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\S-1-5-21-2416424366-1165671203-1984061266-1001\\System\\GameConfigStore");
	for(const auto& child : GameConfigStore->GetSubKey("Children")->GetSubKeys())
		child.second->GetValue("GameDVR_GameGUID")->Set(Randomizer::DashedString(8, 4, ALLOW_NONE_CAPITALS | ALLOW_NUMBERS));
	
	//TODO: Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-2416424366-1165671203-1984061266-1001
	//TODO: Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}
}

void Spoof::SpoofWindows()
{
	Registry* windows = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
	windows->GetValue("DigitalProductId")->Set(Randomizer::Binary(0xA0 * 2));
	windows->GetValue("DigitalProductId4")->Set(Randomizer::Binary(0x4F8 * 2));
	windows->GetValue("InstallDate")->Set(Randomizer::Integer(1623000000, 1623001747));
	windows->GetValue("ProductId")->Set(Randomizer::DashedString(5, 3, ALLOW_NUMBERS | ALLOW_CAPITALS));
	windows->GetValue("UBR")->Set(Randomizer::Integer(1000, 1099));
	windows->GetValue("InstallTime")->Set(Randomizer::Integer(1000000000, 2000000000));
	
	Registry* windows2 = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform");
	windows2->GetValue("BackupProductKeyDefault")->Set(Randomizer::DashedString(5, 4, ALLOW_CAPITALS | ALLOW_NUMBERS));
	windows2->GetValue("actionlist")->Set(Randomizer::Binary(50));
	windows2->GetValue("LicStatusArray")->Set(Randomizer::Binary(300));
	windows2->GetValue("PolicyValuesArray")->Set(Randomizer::Binary(300));
	windows2->GetValue("ServiceSessionId")->Set(Randomizer::Binary(100));
	windows2->GetSubKey("Activation")->GetValue("ProductActivationTime")->Set(Randomizer::Integer(1000000000, 2000000000));
	
	Registry* explorer = RegistryManager::CreateRegistry("Computer\\HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer");
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
	
	Registry* WindowsUpdate = RegistryManager::CreateRegistry("Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate");
	WindowsUpdate->GetValue("SusClientIdValidation")->Set(Randomizer::Binary(200));
	for(const auto& value: WindowsUpdate->GetValues())
	{
		std::string id = value.first.substr(value.first.size() - 2);
		std::transform(id.begin(), id.end(), id.begin(), [](char c)
		{
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
	Registry* software = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\S-1-5-21-2416424366-1165671203-1984061266-1001\\SOFTWARE");
	software->Delete("Facepunch Studios LTD");
	
	Registry* unistall = RegistryManager::CreateRegistry("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
	unistall->Delete("Steam App 252490");
	
	Registry* GameConfigStore = RegistryManager::CreateRegistry("Computer\\HKEY_USERS\\S-1-5-21-2416424366-1165671203-1984061266-1001\\System\\GameConfigStore");
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
	
}