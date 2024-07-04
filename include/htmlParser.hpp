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
			SKIP,
			S,
			R,
			C,
			SRC_ATTR,
			PROCESS_SRC_ATTR,
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

		~Parser() noexcept;

	private:
		bool wcstombs_on_skip(char& ch, wchar_t& w_ch) const noexcept;
		std::wifstream file;
		int state;
		// std::locale loc = std::locale("en_US.UTF-8");

	};
}; // namespace HTML

#endif // HTML_PARSER_HPP
