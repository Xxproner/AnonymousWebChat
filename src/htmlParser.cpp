#include <string>
#include <iostream>

#include "htmlParser.hpp"
/**
 * state finite machine 
 * */


int HTML::Parser::init(const char* path)
{
	// file.close()
	file.open(path, std::ios_base::in);
	if (!file.is_open())
	{
		return -1;
	}
	
	// std::locale::global(loc);
	// std::wcin.imbue(loc);
	state = SKIP;
	return 0;
}


void HTML::Parser::clear() noexcept
{
	state = SKIP;
	file.close();
	// std::wcin.imbue(std::locale::classic());
	// std::locale::global(std::locale::classic());
}

// read it by another way word by word
// now method is char by char
std::wstring HTML::Parser::parse() noexcept
{
	std::wstring src;
	size_t src_len = 0;

	auto end_of_file = file.eof();

	wchar_t ch; // if % it may be unicode character
	wchar_t weof = std::char_traits<wchar_t>::eof();
	while((ch = file.get()) != weof)
	{
		// std::wcout << ch;
		switch(ch)
		{
			case L'S':
			case L's':
			{
				if (state == SKIP)
				{
					state = S;
				} else if (state == PROCESS_SRC_ATTR)
				{
					src.push_back(ch);
					++src_len;
				}else 
				{
					state = SKIP;
				}
				break;
			}
			case L'R':
			case L'r':
			{
				if (state == S)
				{
					state = R;
				} else if(state == PROCESS_SRC_ATTR)
				{
					src.push_back(ch);
					++src_len;
				} else 
				{
					state = SKIP;
				}
				break;
			}
			case L'C':
			case L'c':
			{
				if (state == R)
				{
					state = C;
				} else if(state == PROCESS_SRC_ATTR)
				{
					src.push_back(ch);
					++src_len;
				} else 
				{
					state = SKIP;
				}
				break;
			}
			case L' ': // whitespace
			{
				if (state == C || state == SRC_ATTR)
				{
					// nothing
				} else if (state == PROCESS_SRC_ATTR)
				{
					src.push_back(ch);
					++src_len;
				} else 
				{
					state = SKIP;
				}
				break;
			}
			case L'=':
			{
				if (state == C)
				{
					state = SRC_ATTR;
				} else if (state == PROCESS_SRC_ATTR)
				{
					src.push_back(ch);
					++src_len;
				} else 
				{
					state = SKIP;
				}
				break;
			}
			case L'\"': // not allowed in file name
			case L'\'': 
			{
				if (state == SRC_ATTR)
				{
					state = PROCESS_SRC_ATTR;
				} else if (state == PROCESS_SRC_ATTR)
				{
					if (ch == '\"')
					{
						// state = END_SRC_ATTR;
						state = SKIP;
						return src;
					} else 
					{
						src.push_back(ch);
						++src_len;
					}
					
					break;
				} else 
				{
					state = SKIP;
				}
				break;
			}
			// case L'\n':
			// {
			// 	if (state != PROCESS_SRC_ATTR)
			// 	{
			// 		state = SKIP;
			// 	}
			// }
			default:
			{
				if (state == PROCESS_SRC_ATTR)
				{
					// allowed sybmol for file
					src.push_back(ch);
					++src_len;
				} else 
				{
					state = SKIP;
				}
				break;
			}
		}
	}

	return L"";
};

HTML::Parser::~Parser() noexcept
{
	file.close();
}

