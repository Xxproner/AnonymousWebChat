#include <string>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <type_traits>

#include "htmlParser.hpp"

/**
 * return: pair of number readed characters and delimiter */
std::pair<std::size_t, wchar_t> HTML::Parser::GetWord(wchar_t* word, std::size_t size)
{
    wchar_t ch = 0;
    size_t readed_chars = 0;
    while(file.get(ch) &&
        --size > 0)
    {
        if (std::find(html_delims, end_html_delims, ch) != end_html_delims)
        {
            word[readed_chars] = L'\0';
            return {readed_chars, ch};
        }

        word[readed_chars] = ch;
        ++readed_chars;
    }
    
    if (file.fail() && !file.eof())
    {
        // think about recovering
        std::cerr << "Unexpected error while io!\n";
        return {-1, L'\0'};
    }
    
    word[readed_chars] = L'\0';
    return {readed_chars, std::type_traits<wchar_t>::eof()};
}


int HTML::Parser::init(const char* path)
{
	/* clear resources */
	file.close();

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

bool HTML::Parser::wcstombs_on_skip(char& ch, wchar_t& w_ch) const noexcept
{
	bool flag = true;
	if (wcstombs(&ch, &w_ch, 1) == -1) // fail
	{
		flag = false;
	}
	
	return flag;
}

void HTML::Parser::ChangeStateByDelim(wchar_t html_delim)
{
	switch(html_delim)
	{
		case L'<':
		{
			state = OPEN_TAG;
			break;
		}
		case L'>':
		{
			state = CLOSE_TAG;
			break;
		}
		case L'=':
		{
			break;
		}
	}
}

// read it by another way word by word
// now method is char by char
std::string HTML::Parser::parse() noexcept
{
	std::string src;
	size_t src_len = 0;
	char simple_ch = 0;
	
	auto end_of_file = file.eof();

	wchar_t ch; // if % it may be unicode character
	// wchar_t weof = std::char_traits<wchar_t>::eof();

	const size_t kLenWord  = 64;
	wchar_t word[kLenWord];
	
	const size_t kLenTag = 16;
	wchar_t tag[kLenTag];

	const size_t kLenAttr = 24;
	wchar_t attr[kLenAttr];

	size_t num_readed_chars = 0;

	while(!file)
	{
		auto num_rdd_ch_n_delim = GetWord(word, kLenWord);
		
		if (num_rdd_ch_n_delim.first == -1)
		{
			return -1;
		} else if (num_rdd_ch_n_delim.first == 0)
		{
			// check delimiter
			ChangeStateByDelim(num_rdd_ch_n_delim.second);
		} else
		{
			switch (state)
			{
				case OPEN_TAG:
				{
					// <tag> or </tag>
					if (strcmp(word, "link") == 0)
					{
						state = LINK_TAG;
					}
				}
				case CLOSE_TAG:
				{
					state = INIT;
				}
				case LINK_TAG:
				{
					// attribute process
					
				}

			}
		}


		/*switch(ch)
		{
			case L'S':
			case L's':
			{
				if (state == SKIP)
				{
					state = S;
				} else if (state == PROCESS_SRC_ATTR)
				{
					if (wcstombs_on_skip(simple_ch, ch))
					{
						src.push_back(simple_ch);
						++src_len;
					}else
					{
						state = SKIP;
					}
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
					if (wcstombs_on_skip(simple_ch, ch))
					{
						src.push_back(simple_ch);
						++src_len;
					}else
					{
						state = SKIP;
					}
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
					if (wcstombs_on_skip(simple_ch, ch))
					{
						src.push_back(simple_ch);
						++src_len;
					}else
					{
						state = SKIP;
					}
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
					if (wcstombs_on_skip(simple_ch, ch))
					{
						src.push_back(simple_ch);
						++src_len;
					}else
					{
						state = SKIP;
					}
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
					if (wcstombs_on_skip(simple_ch, ch))
					{
						src.push_back(simple_ch);
						++src_len;
					}else
					{
						state = SKIP;
					}
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
						if (wcstombs_on_skip(simple_ch, ch))
						{
							src.push_back(simple_ch);
							++src_len;
						}else
						{
							state = SKIP;
						}
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
					if (wcstombs_on_skip(simple_ch, ch))
					{
						src.push_back(simple_ch);
						++src_len;
					}else
					{
						state = SKIP;
					}
				} else 
				{
					state = SKIP;
				}
				break;
			}
		}*/

	}

	return "";
};

HTML::Parser::~Parser() noexcept
{
	file.close();
}

