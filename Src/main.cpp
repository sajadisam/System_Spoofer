#include "Spoof/Spoof.h"
#include "Util/Util.h"
#include "Util/Randomizer.h"
#include "Registry/RegistryManager.h"

// Computer\HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\
// ^ CPU

int main(int argc, char** argv)
{
	spdlog::set_level(spdlog::level::trace);
	Spoof::Initialize();
	//std::cout << "Exists: " << IsKeyExist(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Dfrg") << std::endl;
	//DisableEnableConnections(false);
	//DisableEnableConnections(true);
	return 0;
}