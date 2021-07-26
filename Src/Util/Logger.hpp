/*
 * @author Xelian on 7/24/2021.
 */

#pragma once
#define SPDLOG_WCHAR_TO_UTF8_SUPPORT

#include "spdlog/spdlog.h"

#if defined(EmberBuild_Debug) || defined(EmberBuild_RelWithDebInfo)
	#define EMBER_TRACE(...) spdlog::trace(__VA_ARGS__)
	#define EMBER_ERROR(...) spdlog::error(__VA_ARGS__)
	#define EMBER_WARN(...) spdlog::warn(__VA_ARGS__)
	#define EMBER_DEBUG(...) spdlog::debug(__VA_ARGS__)
	#define EMBER_INFO(...) spdlog::info(__VA_ARGS__)
#else
	#define EMBER_TRACE(...)
	#define EMBER_ERROR(...)
	#define EMBER_WARN(...)
	#define EMBER_DEBUG(...)
	#define EMBER_INFO(...)
#endif