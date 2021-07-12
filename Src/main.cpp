#include "Registry/RegistryManager.h"
#include "Spoof/Spoof.h"
#include "Util/Util.h"

// Computer\HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\
// ^ CPU

// Computer\HKEY_LOCAL_MACHINE\HARDWARE\DEVICEMAP\VIDEO
//^ Interesting

int main(int argc, char** argv)
{
	spdlog::set_level(spdlog::level::trace);
	Spoof::Initialize();

	//DisableEnableConnections(false);
	//DisableEnableConnections(true);
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