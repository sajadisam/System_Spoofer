//
// Created by Xelian on 2021-06-29.
//
#pragma once

#include "../Registry/Registry.h"

class Spoof
{
public:
	Spoof() = delete;
	~Spoof() = delete;
public:
    static void Initialize();
	static void SpoofDisplay();
    static void SpoofGPU();
    static void SpoofDrives();
private:
    /* Monitor */
    static void SpoofEnumDisplay();
    static void SpoofEnumAudio();
    static void SpoofEnumHID();
private:
    static void SpoofEnum(Registry* registry,const std::string& randomClassGUID);
};
