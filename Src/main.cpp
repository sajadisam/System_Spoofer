#include "Registry/Registry.h"
#include "Registry/RegistryManager.h"
#include "Util/Randomizer.h"
#include "Spoof/Spoof.h"

// Computer\HKEY_LOCAL_MACHINE\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 1\Target Id 0\Logical Unit Id 0
// ^ Disk 1

// Computer\HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\
// ^ CPU

// Computer\HKEY_LOCAL_MACHINE\HARDWARE\DEVICEMAP\VIDEO
//^ Interesting

int main()
{
    spdlog::set_level(spdlog::level::trace);
	Spoof::Initialize();
    RegistryManager::SaveValues();
    //while(true)
    //    if(GetAsyncKeyState(VK_F3) & 1)
    //        RegistryManager::ResetValues();
    //    else if(GetAsyncKeyState(VK_F4) & 1)
    //        break;
	return 0;
}

void BackUpAndReset()
{
	RegistryManager::SaveValues();
	while(true)
		if(GetAsyncKeyState(VK_F3) & 1)
			RegistryManager::ResetValues();
		else if(GetAsyncKeyState(VK_F4) & 1)
			break;
}