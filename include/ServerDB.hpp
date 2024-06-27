#ifndef SERVERDB_HPP_
#define SERVERDB_HPP_

#include <stdio.h>
#include <string.h>

#include <mutex>
#include <functional>

#include "DB.hpp"
#include "Participant.hpp"

class serverDB : public DB
{
private:
  
  using attr_n_type = std::pair<const char*, const char*>;
  using tableMetaData = const std::array<attr_n_type, 3>;
  size_t users_num = 1;
  tableMetaData tableInfo = { attr_n_type{"id", "INTEGER PRIMARY KEY"},
                              attr_n_type{"pseudo", "VARCHAR(30)"},
                              attr_n_type{"key", "VARCHAR(30)"} };
  mutable std::mutex db_mutex;

  class server_db_internal_error : public std::runtime_error
  {
    std::string m_error;
    public:
      // server_db_internal_error() = default;
      server_db_internal_error(const char* errormsg) : 
        std::runtime_error(errormsg), m_error("DB internal exception : ")
      {
        m_error.append(errormsg);
      }

      server_db_internal_error(const std::string& errormsg) : 
        std::runtime_error(errormsg), m_error("DB internal exception : ")
      {
        m_error.append(errormsg);
      }

      server_db_internal_error(const server_db_internal_error& another) noexcept :
        std::runtime_error(another)
      { 
        m_error.assign(another.what());
      }

      const server_db_internal_error& 
        operator=(const server_db_internal_error& another) noexcept
      {
        m_error.assign(another.what());
        return *this;
      }

      virtual const char* what() const noexcept override
      {
        return m_error.c_str();
      }

      ~server_db_internal_error() = default;
  };

  static int CountRecords_callback(void* data, int clm_num, char** fields, char** clm_names)
  {
    int *data_ptr = reinterpret_cast<int*>(data);
    *data_ptr += 1;
    return 0;
  }

  static int CountRecords_inTable(void* data, int clm_num, char** fields, char** clm_names)
  {
    if (std::char_traits<char>::compare(clm_names[0], "NUM", 3) == 0 && 
      clm_num == 1)
    {
      *reinterpret_cast<size_t*>(data) = static_cast<size_t>(atoi(fields[0]));
    } else 
      return 1;
    return 0;
  }

public:
  enum
  {
    DB_OK = 0,
    DB_OPN_ERROR,
    DB_EXEC_ERROR,
    DB_UNSPEC_ERROR,
    DB_NAME_BUSY,
    DB_ACCS_DENIED,

  };

  serverDB() = default;

  int16_t open(const char* filename);

  int16_t AddParticipant(const Participant& member_info);

  int16_t AccessParticipant(const Participant& member_info) const ;

  // void close();

  ~serverDB() = default;
};

#endif // SERVERDB_HPP_