//
// Created by Xelian on 2021-06-19.
//
#include "Randomizer.h"

static const std::string s_SmallAlphabets = "qwertyuiopasdfghjklzxcvbnm";
static const std::string s_BigAlphabets = "QWERTYUIOPASDFGHJKLZXCVBNM";
static const std::string s_Symbols = "!\"#%&/()=?@{[]}\\|<>";
static const std::string s_Numbers = "123456789";

int Randomizer::Integer(int min, int max)
{
	assert(max > min);
	std::random_device seeder;
	std::mt19937 engine(seeder());
	std::uniform_int_distribution<int> dist(min, max);
	return dist(engine);
}

std::string Randomizer::String(int length, int flags)
{
	std::string buffer;
	buffer.resize(length);
	std::string result;
	if(flags & RandomStringFlags::ALLOW_NONE_CAPITALS)
		result = s_SmallAlphabets;
	if(flags & RandomStringFlags::ALLOW_CAPITALS)
		result += s_BigAlphabets;
	if(flags & RandomStringFlags::ALLOW_SYMBOLS)
		result += s_Symbols;
	if(flags & RandomStringFlags::ALLOW_NUMBERS)
		result += s_Numbers;
	
	if(result.empty())
		return result;
	
	for(int i = 0; i < length; ++i)
	{
		const int& random = Integer(0, result.size() - 1);
		buffer[i] = result[random];
	}
	return buffer;
}

float Randomizer::Float(float min, float max)
{
	assert(max > min);
	srand(Randomizer::Integer(INT32_MAX - INT16_MAX, INT32_MAX));
	float random = ((float)rand()) / (float)RAND_MAX;
	float range = max - min;
	return (random * range) + min;
}

std::vector<BYTE> Randomizer::Binary(int length)
{
	std::vector<BYTE> buffer;
	buffer.resize(length);
	for(int i = 0; i < length; ++i)
	{
		const int& random = Integer(0, 255);
		buffer[i] = *(BYTE*)&random;
	}
	return buffer;
}

std::string Randomizer::DashedString(int charlength, int dashes, int flags)
{
	std::string buffer;
	buffer.reserve((charlength * dashes) + (dashes * 2));
	buffer += String(charlength, flags);
	for(int i = 0; i < dashes; ++i)
		buffer += "-" + String(charlength, flags);
	
	return buffer;
}