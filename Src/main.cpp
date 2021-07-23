#include "Spoof/Spoof.h"

// Computer\HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\
// ^ CPU

int main(int argc, char** argv)
{
	spdlog::set_level(spdlog::level::trace);
	Spoof::Initialize();
	//Spoof::SpoofMac();
	//DisableEnableConnections(false);
	//DisableEnableConnections(true);
	return 0;
}