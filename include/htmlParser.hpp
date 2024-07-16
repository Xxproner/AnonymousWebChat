#ifndef HTML_PARSER_HPP
#define HTML_PARSER_HPP

#include <fstream>
#include <string>

namespace HTML
{
	class Parser
	{
		enum 
		{
			INIT,
			OPEN_TAG,
			LINK_TAG,
			CLOSE_TAG,
			ATTR
			// SKIP,
			// S,
			// R,
			// C,
			// SRC_ATTR,
			// PROCESS_SRC_ATTR,
			// END_SRC_ATTR
			// i add END_SRC_ATTR for html error
			// for example letter sybmol after: src = "hello"3
		};


	public:
		Parser() = default;

		int init(const char* path);

		void clear() noexcept;


		/**
		 * the function returns path to src 
		 * if no more src empty string
		 * */
	
		std::string parse() noexcept;
		// std::string parse() noexcept;

		~Parser() noexcept;

	private: // private methods
		bool wcstombs_on_skip(char& ch, wchar_t& w_ch) const noexcept;
		
		void ChangeStateByDelim(wchar_t html_delim);

		std::pair<std::size_t, wchar_t> GetWord(wchar_t* word, std::size_t count);
	private: // private members
		std::wifstream file;
		int state;


		static const wchar_t html_delims[] = L" <>=\t\n";

    	static const wchar_t* end_html_delims = html_delims + wcslen(html_delims);
		
		// std::locale loc = std::locale("en_US.UTF-8");

	};
}; // namespace HTML

#endif // HTML_PARSER_HPP
