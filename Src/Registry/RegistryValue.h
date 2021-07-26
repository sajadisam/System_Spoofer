//
// Created by Xelian on 2021-06-18.
//

#define ENABLE_SET 1
#define ENABLE_DELETE 1

class RegistryValue
{
public:
	RegistryValue(HKEY& key, const std::string& name, DWORD type, nlohmann::json& saves);
public:
	__forceinline const std::string& GetName() const
	{
		if(!this)
			return "NULL";
		return this->m_Name;
	}
	
	__forceinline DWORD GetType() const
	{
		return !this ? 0 : this->m_Type;
	}

public:
	void Set(int type, void* buffer, int size);
	void Set(std::string str);
	void Set(const std::vector<int>& binary);
	void Set(const std::vector<BYTE>& binary);
	void Set(int number);
	void Delete();
	template<typename Type>
	Type Value();

private:
	void CheckKeyValue(LRESULT error);
	DWORD GetBufferSize(const std::string& name);
private:
	std::vector<int> ReadBinaryAsInt();
	std::vector<BYTE> ReadBinaryAsByte();
	std::string ReadString();

private:
	HKEY& m_Key;
	std::string m_Name;
	DWORD m_Type;
	nlohmann::json& m_Saves;
	nlohmann::json m_Value;
};

template<typename Type>
Type RegistryValue::Value()
{
	if(!this)
		return Type{};
	
	if(m_Type == REG_NONE)
		return Type{};
	try
	{
		if constexpr(std::is_same_v<Type, std::string>)
			return ReadString();
		
		if constexpr(std::is_same_v<Type, const char*>)
			return ReadString().c_str();
		
		if constexpr(std::is_same_v<Type, std::remove_const<char*>::type>)
			return const_cast<char*>(ReadString().c_str());
		
		if constexpr(std::is_same_v<Type, std::vector<int>>)
			return ReadBinaryAsInt();
		
		if constexpr(std::is_same_v<Type, std::vector<BYTE>>)
			return ReadBinaryAsByte();
		
		Type buffer;
		DWORD size = GetBufferSize(m_Name.c_str());
		CheckKeyValue(RegQueryValueEx(m_Key, m_Name.c_str(), NULL, &m_Type, (LPBYTE)&buffer, &size));
		return buffer;
	} catch(std::exception& e)
	{
		EMBER_ERROR("[ERROR READING] {0}", e.what());
		return Type{};
	}
}