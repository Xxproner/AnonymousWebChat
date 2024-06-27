#include "htmlUtils.hpp"

#include <string.h>

#include <iostream>
#include <string_view>
#include <map>
#include <regex>

/**
 *  return type: name of file and stream associated with it
*/
std::pair<std::string, std::ofstream> HTML::CopyFileChangeTAGvalue(
		const std::string& from_file_name, std::initializer_list<id_n_value> values_list) noexcept(false)
{
	// const size_t html_src_path_length = from_file_name.length();
	std::ifstream from_file (from_file_name, std::ios_base::in | std::ios_base::binary);

	std::string to_file_name(from_file_name);
	NameFileAPPCokkies(to_file_name);
	
	std::ofstream to_file(to_file_name, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);

	if (!from_file.is_open() || !to_file.is_open())
	{
		if (!from_file.is_open())
		{
			std::cerr << "HTML::CopyFileChangeTAGvalue() error: source file is not opened!";
		} else 
		{
			from_file.close();
		}

		if (!to_file.is_open()){
			std::cerr << "HTML::CopyFileChangeTAGvalue() error: dest file is not opened!";
		} else 
		{
			to_file.close();
		}

		return std::make_pair<std::string, std::ofstream>("", std::move(to_file));
	}

	std::map<std::string_view, std::string_view> values_map;

	std::string finding_ids = "\\sid\\s*=\\s*\"(";
	
	for(auto iter = values_list.begin(); iter != values_list.end(); ++iter)
	{
		if (iter != values_list.begin())
		{
			finding_ids.push_back('|');
		}

		values_map.emplace(iter->first, iter->second);
		finding_ids.append(iter->first);
	}

	finding_ids.append(")\"\\s*");
	std::regex id_regex(finding_ids);

	std::string_view value_attr = " value"; 

	std::string line;
	while (std::getline(from_file, line))
	{
		std::smatch sm;
	    if (regex_search(line, sm, id_regex))
	    {	
	    	std::string_view id{sm[1].str()}; // captute group
	    	auto iter = values_map.find(id);
	    	
			size_t pos = line.find(value_attr);
			if (pos == std::string::npos)
			{
				std::cerr << "HTML::CopyFileChangeTAGvalue() error: id was found but not value(in one string)";
				return std::make_pair<std::string, std::ofstream>("", std::move(to_file));
			}

			size_t first_quote_pos = line.find("\"", pos) + 1;
			size_t last_quote_pos = line.find("\"", first_quote_pos);

			line.replace(first_quote_pos, last_quote_pos - first_quote_pos, iter->second);
	    }

		to_file << line << '\n';
	}

	return std::make_pair<std::string, std::ofstream>(std::move(to_file_name), std::move(to_file));
}

void HTML::AddJSAlert(std::ofstream& file, const char* msg)
{
	if (!file.is_open())
	{
		std::cerr << "HTML::AddJSAlert() error: File must be opened!\n";
		return ;
	}

	file.write("\n<script> alert(\"", strlen("\n<script> alert(\"")).write(
		msg, std::char_traits<char>::length(msg)).write(
			"\")</script>\n", strlen("\")</script>\n"));
}

void HTML::ReadFilebyWord(const char* file_name) noexcept(false)
{
	std::ifstream file (file_name, std::ios_base::in | std::ios_base::binary);
	std::string word;
	if (!file.is_open())
		throw std::runtime_error("File open error");
	while(file >> word)
	{
		std::cout << word << '\n';
	}

	file.close();
}

void HTML::NameFileAPPCokkies(std::string& file_name)
{
	size_t file_type_idx = file_name.rfind('.');

	file_name.insert(file_type_idx, "_Cokkies");
}

