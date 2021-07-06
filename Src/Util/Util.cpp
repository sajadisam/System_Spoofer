//
// Created by Xelian on 2021-06-20.
//
#include "Util.h"

std::vector<std::string> SegmentPhrase(const std::string &phrase, char splitter)
{
    std::vector<std::string> data;
    std::stringstream ss(phrase);
    while (ss.good()) {
        std::string substr;
        getline(ss, substr, splitter);
        data.push_back(substr);
    }
    return data;
}

std::vector<int> StringToVector(const std::string &str) {
    return std::vector<int>(str.begin(), str.end());
}