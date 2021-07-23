//
// Created by Xelian on 2021-06-19.
//

enum RandomStringFlags
{
	NONE, ALLOW_NONE_CAPITALS = 1 << 1, ALLOW_CAPITALS = 1 << 2, ALLOW_SYMBOLS = 1 << 3, ALLOW_NUMBERS = 1 << 4
};

class Randomizer
{
public:
	static int Integer(int min, int max);
	static float Float(float min, float max);
	static std::string String(int length, int flags = NONE);
	static std::string DashedString(int charlength, int dashes, int flags = NONE);
	static std::vector<BYTE> Binary(int length);
};