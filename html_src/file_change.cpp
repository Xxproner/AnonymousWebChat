#include <string.h>

#include <iostream>
#include <fstream>
#include <string>
#include <exception>
#include <new>
#include <forward_list>

class HTML
{  
  // think about realization opening file while program is finished!
public:
  using pos_type = std::ifstream::pos_type;

  /*
  static void CopyFileChangeTAGvalue(const char* from_file_name, const char* id, const char* value) noexcept(false)
  {
    // use stack for specific sybmols like ' < > " etc
    std::ifstream from_file (from_file_name, std::ios_base::in | std::ios_base::binary);
    
    std::string to_file_name = from_file_name;
    NameFileAPPCokkies(to_file_name);
    std::ofstream to_file(to_file_name, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);

    if (!from_file.is_open() || !to_file.is_open())
      throw std::runtime_error("Open file error");
    // from_file.exceptions(std::ifstream::eofbit);

    std::string id_str;  // id='${id}'
    {
      id_str.reserve(5u + strlen(id));
      id_str.append("id='").append(id).append("'");
    }

    bool opened_tag = false;
    const char* value_attr = "value=";

    char ch;
    while ((ch = from_file.get()) != std::char_traits<char>::eof()) // read full file
    {
      to_file.put(ch);


      if (ch == '<' && !opened_tag)
        opened_tag = true;
      else if (ch == '<')
        throw std::runtime_error("Error in html(open tag symbol twice)!");
      else if (ch == '>' && opened_tag)
        opened_tag = false;

      else if (ch == 'i') // maybe <id=>
      {
        size_t id_idx = 0;
        while(ch != std::char_traits<char>::eof() && 
          ch == id_str[id_idx] && id_idx != id_str.length()) 
        { 
          ch = from_file.get();
          to_file.put(ch); 
          ++id_idx;
        }

        if (ch == std::char_traits<char>::eof())
          break;

        if (ch == ' ' && id_idx == id_str.length() && opened_tag ) // what we what
        {
          // find value=''
          while(((ch = from_file.get()) != std::char_traits<char>::eof()) && opened_tag)
          {
            to_file.put(ch);

            if (ch == '<')
              throw std::logic_error("Error in html(open tag symbol twice)!");
            else if (ch == '>' && opened_tag)
              opened_tag = false;
            
            else if (ch == 'v') // maybe value=
            {
              size_t value_idx = 0;
              while(ch != std::char_traits<char>::eof() &&
                ch == value_attr[value_idx] && value_idx != strlen(value_attr))
              {
                ch = from_file.get();
                to_file.put(ch);
                ++value_idx;
              }

              if (ch == std::char_traits<char>::eof())
                break;

              if (ch == '\'' && value_idx == strlen(value_attr) && opened_tag) // found
              {
                // from_file : value='...' 
                // to_file : value='...'

                to_file.write(value, strlen(value)).put('\'');

                // if that is not value attribute then algorithm is not correct
                while((ch = from_file.get()) != std::char_traits<char>::eof() && ch != '\'') {   }

                if (ch == std::char_traits<char>::eof())
                  break;

              } else if (ch == '<' && !opened_tag)
                  opened_tag = true;
                else if (ch == '<')
                  throw std::runtime_error("Error in html(open tag symbol twice)!");
                else if (ch == '>' && opened_tag)
                  opened_tag = false;
            }
          }

          if (ch == std::char_traits<char>::eof())
            throw std::runtime_error("value attribute is not found");
          
        } else if (ch == '<' && !opened_tag)
            opened_tag = true;
          else if (ch == '<')
            throw std::runtime_error("Error in html(open tag symbol twice)!");
          else if (ch == '>' && opened_tag)
            opened_tag = false;
      }
    }

    to_file.close();
    from_file.close();
  }

  // add variadic template for pairs { id , new value }...
  static void CopyFileChangeTAGvalue(const char* from_file_name, const char* id, const char* value, int) noexcept(false)
  {
    std::ifstream from_file (from_file_name, std::ios_base::in | std::ios_base::binary);
    std::string to_file_name = from_file_name;
    NameFileAPPCokkies(to_file_name);
    std::ofstream to_file(to_file_name, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);

    if (!from_file.is_open() || !to_file.is_open())
      throw std::runtime_error("Open file error");
    // from_file.exceptions(std::ifstream::eofbit);
    std::string id_str;  // id='${id}'
    {
      id_str.reserve(5u + strlen(id));
      id_str.append("id='").append(id).append("'");
    }

    std::string value_str; // value='${value}'
    {
      value_str.reserve(8u + strlen(value));
      value_str.append("value='").append(value).append("'");
    }
    const char* value_attr = "value="; // literal ""s

    char ch;
    std::string word;
    while (from_file >> word)
    {
      if (word.empty())
      {
        to_file.put('\n');
        continue;
      }

      size_t id_idx;
      if ((id_idx = word.find(id_str)) != std::string::npos)
      {
        to_file << word;
        while(from_file >> word)
        {
          if (word.empty())
          {
            to_file.put('\n');
            continue;
          }

          size_t value_start_idx; 
          if ((value_start_idx = word.find(value_attr)) != std::string::npos) // value should be there otherwise the case is bad
          {
            size_t value_end_idx = word.rfind('\'');

            word.replace(value_start_idx, value_end_idx - value_start_idx + 1u, value_str);
          }

          to_file << word;

          if ((ch = from_file.peek()) == '\n' || ch == ' ')
          {
            from_file.get() ;
            to_file.put(ch);
          }
        }
        // find value
      }

      to_file << word;
      if ((ch = from_file.peek()) == '\n' || ch == ' ')
      {
        from_file.get() ;
        to_file.put(ch);
      }
    }


    to_file.close();
    from_file.close();

  }
  */


  using id_n_value = std::pair<const char*, const char*>;
  static std::string CopyFileChangeTAGvalue(
    const char* from_file_name, std::initializer_list<id_n_value> values_list) noexcept(false)
  {
    std::ifstream from_file (from_file_name, std::ios_base::in | std::ios_base::binary);
    std::string to_file_name = from_file_name;
    NameFileAPPCokkies(to_file_name);
    std::ofstream to_file(to_file_name, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);

    if (!from_file.is_open() || !to_file.is_open())
      throw std::runtime_error("Open file error");
    // from_file.exceptions(std::ifstream::eofbit);

    std::forward_list<id_n_value> id_n_valueList; 
    auto TerminateWork = [&from_file, &to_file, &id_n_valueList] ()
    {
      if (from_file.is_open()) from_file.close();
      if (to_file.is_open()) to_file.close();
      for (const auto& id_n_value : id_n_valueList)
      {
        delete[] id_n_value.first;
      }
    };

    char *buf; size_t buf_size = 16; size_t needed_buf_size = 6u;
    for (auto iter = values_list.begin(); iter != values_list.end(); ++iter)
    {
      needed_buf_size += strlen(iter->first);
      if (needed_buf_size > buf_size)
      {
        while(buf_size < needed_buf_size)
          buf_size *= 2;

      }

      buf = new(std::nothrow) char[buf_size];
      if (!buf) { TerminateWork(); throw std::bad_alloc(); }

      sprintf(buf, "id='%s'", iter->first);
      id_n_valueList.emplace_front(buf, iter->second);
    }

    const char* value_attr = "value="; // literal ""s

    char ch;
    std::string word;
    while (from_file >> word)
    {
      if (word.empty())
      {
        to_file.put('\n');
        continue;
      }

      size_t id_idx; 
      auto prev_iter = id_n_valueList.cbefore_begin();
      for (auto iter = std::next(prev_iter); iter != id_n_valueList.cend(); ++iter, ++prev_iter)
      {
        if ((id_idx = word.find(iter->first)) != std::string::npos)
        {
          to_file << word;

          if ((ch = from_file.peek()) == '\n' || ch == ' ')
          {
            from_file.get() ;
            to_file.put(ch);
          }

          size_t value_start_idx; 
          while(from_file >> word && (value_start_idx = word.find(value_attr)) == std::string::npos)
          {
            to_file << word;
            if ((ch = from_file.peek()) == '\n' || ch == ' ')
            {
              from_file.get() ;
              to_file.put(ch);
            }
          }
            
          if (value_start_idx != std::string::npos) // value should be there otherwise the case is bad
          {
            value_start_idx = word.find('\'', value_start_idx + 1);
            size_t value_end_idx = word.rfind('\'');

            word.replace(value_start_idx + 1, value_end_idx - value_start_idx - 1u, iter->second);

            delete[] iter->first;
            id_n_valueList.erase_after(prev_iter);
            break;
          }

          TerminateWork(); throw std::logic_error("Not `value' attribute for id");
        }
      }

      to_file << word;
      if ((ch = from_file.peek()) == '\n' || ch == ' ')
      {
        from_file.get() ;
        to_file.put(ch);
      }
    }


    TerminateWork();
    return to_file_name;
  }

  static void AddJSAlert(const char* file_name, const char* msg)
  {
    std::ofstream file(file_name, std::ios_base::out | std::ios_base::app);

    if (!file.is_open())
    {
      std::cerr << "File is not open!";
      return ;
    }

    file.write("\n<script> alert(\"", strlen("\n<script> alert(\"")).write(
      msg, std::char_traits<char>::length(msg)).write(
        "\")</script>\n", strlen("\")</script>\n"));

    file.close();
  }

  static void ReadFilebyWord(const char* file_name) noexcept(false)
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

private:
  static void NameFileAPPCokkies(std::string& file_name)
  {
    size_t file_type_idx = file_name.rfind('.');

    file_name.insert(file_type_idx, "_Cokkies");
  }
};

