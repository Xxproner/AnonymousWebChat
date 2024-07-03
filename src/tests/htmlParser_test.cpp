#include <uchar.h>


#include <iostream>
#include <string>
#include <cassert>
#include <locale>

#define CONCAT(a, b) (a"" b) 

#include "htmlParser.hpp"

int main(int argc, char const *argv[])
{
	std::locale loc = std::locale("en_US.UTF-8");
	std::locale::global(loc);
	// std::string prev_loc = setlocale(LC_ALL, nullptr); // C

	// assert(setlocale(LC_ALL, "en_US.UTF-8") != nullptr);

	HTML::Parser parser;

	assert(parser.init(CONCAT(TEST_FILE_DIR, "test3.html")) == 0 && "Open file error!");

	std::basic_string<wchar_t> src;
	while (!(src = parser.parse()).empty())
	{
		std::wcout << src << '\n';
	}

	parser.clear();

	return 0;
}