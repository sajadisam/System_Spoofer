//
// Created by Xelian on 2021-06-20.
//
#include "Util.h"

std::vector<std::string> SegmentPhrase(const std::string& phrase, char splitter)
{
	std::vector<std::string> data;
	std::stringstream ss(phrase);
	while(ss.good())
	{
		std::string substr;
		getline(ss, substr, splitter);
		data.push_back(substr);
	}
	return data;
}

std::vector<int> StringToVector(const std::string& str)
{
	return std::vector<int>(str.begin(), str.end());
}

/*
 * @credits: https://social.msdn.microsoft.com/Forums/en-US/ad3ae21d-515d-4f67-8519-216f1058e390/enabledisable-network-card?forum=netfxnetcom
 */
HRESULT DisableEnableConnections(BOOL bEnable)
{
	HRESULT hr = E_FAIL;
	CoInitialize(NULL);
	INetConnectionManager* pNetConnectionManager = NULL;
	hr = CoCreateInstance(CLSID_ConnectionManager, NULL, CLSCTX_LOCAL_SERVER | CLSCTX_NO_CODE_DOWNLOAD, IID_INetConnectionManager, reinterpret_cast<LPVOID*>(&pNetConnectionManager));
	if(SUCCEEDED(hr))
	{
		/*
        * Get an enumurator for the set of connections on the system
        */
		IEnumNetConnection* pEnumNetConnection;
		pNetConnectionManager->EnumConnections(NCME_DEFAULT, &pEnumNetConnection);
		
		ULONG ulCount = 0;
		BOOL fFound = FALSE;
		
		hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
		
		HRESULT hrT = S_OK;
		
		/*
        * Enumurate through the list of adapters on the system and look for the one we want
        * NOTE: To include per-user RAS connections in the list, you need to set the COM
        * Proxy Blanket on all the interfaces. This is not needed for All-user RAS
        * connections or LAN connections.
        */
		do
		{
			NETCON_PROPERTIES* pProps = NULL;
			INetConnection* pConn;
			
			/*
			* Find the next (or first connection)
            */
			hrT = pEnumNetConnection->Next(1, &pConn, &ulCount);
			
			if(SUCCEEDED(hrT) && 1 == ulCount)
			{
				/*
				Get the connection properties
				*/
				hrT = pConn->GetProperties(&pProps);
				
				if(S_OK == hrT)
				{
					if(bEnable)
					{
						EMBER_TRACE(L"Enabling adapter: %S\n", pProps->pszwName);
						
						hr = pConn->Connect();
					} else
					{
						EMBER_TRACE(L"Disabling adapter: %S\n", pProps->pszwName);
						hr = pConn->Disconnect();
					}
					
					
					CoTaskMemFree(pProps->pszwName);
					CoTaskMemFree(pProps->pszwDeviceName);
					CoTaskMemFree(pProps);
				}
				pConn->Release();
				pConn = NULL;
			}
		} while(SUCCEEDED(hrT) && 1 == ulCount && !fFound);
		
		if(FAILED(hrT))
			hr = hrT;
		pEnumNetConnection->Release();
	}
	
	if(FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_RETRY))
		EMBER_TRACE("Could not enable or disable connection (0x%08x)\r\n", hr);
	
	pNetConnectionManager->Release();
	CoUninitialize();
	return hr;
}