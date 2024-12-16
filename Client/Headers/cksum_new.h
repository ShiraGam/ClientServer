#pragma once
#ifndef CKSUM_NEW_H
#define CKSUM_NEW_H

#include <iostream>
#include <fstream>
#include <ostream>
#include <cstdio>
#include <vector>
#include <iterator>
#include <filesystem>
#include <string>

unsigned long memcrc(char* b, size_t n);
unsigned long readfile(const std::string& fname);

#endif