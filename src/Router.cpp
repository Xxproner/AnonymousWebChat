#include "Router.hpp"

// class UrlUtils
// {
// public:
	std::vector<std::string_view>
		UrlUtils::Split(const std::string& spliting_string)
	{
		std::vector<std::string_view> splited_url;
		size_t rd_pos = 0;
        size_t curr_len = 0;
    
		for (size_t i = 0; i < spliting_string.length(); ++i)
		{
		    ++curr_len;
			if (spliting_string[i] == '/')
			{
				splited_url.emplace_back(spliting_string.data() + rd_pos, curr_len);
				rd_pos += curr_len;
				curr_len = 0;
			}
		}

        if (rd_pos != spliting_string.length())
        {
            splited_url.emplace_back(spliting_string.data() + rd_pos, curr_len);
        };

		return splited_url; // RNVO
	}
// };