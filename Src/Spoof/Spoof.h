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
	static void SpoofGPU();
	static void SpoofDrives();
	static bool SpoofMac();
	static void SpoofCPU();
	static void SpoofBIOS();
	static void SpoofWindows();
	static void SpoofMisc();
	static void SpoofDisplay();
	static void SpoofEnumAudio();
	static void SpoofEnumHID();
	static void SpoofEnumPCI();
	static void SpoofRust();
	static std::string GetSerialFolder();
private:
};