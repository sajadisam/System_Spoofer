#include "Spoof/Spoof.h"
#include "Util/Util.h"
#include "Util/Randomizer.h"
#include "Registry/RegistryManager.h"
#include <filesystem>

int main(int argc, char** argv)
{
	spdlog::set_level(spdlog::level::trace);
	Spoof::Initialize();
	//DisableEnableConnections(false);
	//DisableEnableConnections(true);
	return 0;
}