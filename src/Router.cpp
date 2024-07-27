#include "Router.hpp"

// class UrlUtils
// {
// public:
	std::vector<std::string_view>
		UrlUtils::Split(std::string_view spliting_string)
	{
		std::vector<std::string_view> splited_url;
		size_t rd_pos = 0;
	    size_t curr_len = 0;

		for (size_t i = 0; i < spliting_string.length(); ++i)
		{
			if (spliting_string[i] == '/')
			{
				splited_url.emplace_back(spliting_string.data() + rd_pos, curr_len);
				rd_pos = i + 1;
				curr_len = 0;
			} else 
			{
			    ++curr_len;
			}
		}

	    if (rd_pos != spliting_string.length())
	    {
	        splited_url.emplace_back(spliting_string.data() + rd_pos, curr_len);
	    };

		return splited_url; // RNVO
	}


	std::vector<std::string>
		UrlUtils::SplitStream(const std::string& spliting_string)
	{
	    std::stringstream ss(spliting_string); 
	    
	    std::string token; 
	    std::vector<std::string> tokens; 
	    
	    char delimiter = '/'; 
	  
	    while (getline(ss, token, delimiter)) { 
	        tokens.push_back(std::move(token)); 
	    }

	    return tokens;
	}
// };