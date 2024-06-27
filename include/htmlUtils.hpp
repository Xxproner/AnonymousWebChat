#ifndef HTML_UTILS_HPP
#define HTML_UTILS_HPP

#include <utility>
#include <fstream>

class HTML
{ 
public:
	// think about realization opening file while program is finished!

	using pos_type = std::ifstream::pos_type;

	using id_n_value = std::pair<std::string_view, std::string_view>;

	/* value of finite machine */
	enum {
		ID_FOUND
	};

	/**
	 *  return type: name of file and stream associated with it
	*/
	static std::pair<std::string, std::ofstream> CopyFileChangeTAGvalue(
		const std::string& from_file_name, std::initializer_list<id_n_value> values_list) noexcept(false);

	static void AddJSAlert(std::ofstream& file, const char* msg);

	static void ReadFilebyWord(const char* file_name) noexcept(false);

	static void NameFileAPPCokkies(std::string& file_name);
};

#endif // HTML_UTILS_HPP