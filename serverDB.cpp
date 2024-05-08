#include <stdio.h>
#include <string.h>

#include <mutex>
#include <new>
#include <functional>

#include "DB.cpp"
#include "Participant.cpp"

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
  serverDB() = default;

  int16_t open(const char* filename)
  {
    // if table does not already exist for some reason
    int exec_code = sqlite3_open(filename, &db);
    if (exec_code)
      throw server_db_internal_error(sqlite3_errmsg(db));

    const char* create_table_cm = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, pseudo VARCHAR(30), key VARCHAR(30));";
    char* status = nullptr;
    if (this->execute(create_table_cm, NULL, NULL, &status) != SQLITE_OK)
    {
      server_db_internal_error ex = server_db_internal_error(status);
      sqlite3_free(status);
      throw ex;
    }

    const char* count_cm = "select count(*) as 'NUM' from users";
    if (this->execute(count_cm, &serverDB::CountRecords_inTable, reinterpret_cast<void*>(&users_num), &status) != SQLITE_OK)
    {
      server_db_internal_error ex = server_db_internal_error(status);
      sqlite3_free(status);
      throw ex;
    }

    users_num += 1; // next id

    return 0;
  }

  int16_t AddParticipant(const Participant& member_info) 
  {
    std::lock_guard<std::mutex> locker(db_mutex);
    
    char* exec_cm = nullptr;
    asprintf(&exec_cm, "SELECT * FROM users WHERE pseudo = \"%s\"", member_info.name_.c_str());
    if (!exec_cm)
      throw std::bad_alloc(); // TODO: 

    int count_record = 0;
    char* status = nullptr;

    if (this->execute(
      exec_cm, &serverDB::CountRecords_callback, reinterpret_cast<void*>(&count_record), &status) != SQLITE_OK) // ? error
    {
      server_db_internal_error ex = server_db_internal_error(status);
      sqlite3_free(status);
      free(exec_cm);
      throw ex;    
    }

    free(exec_cm); exec_cm = nullptr;
    if (count_record != 0) // equal 1 
      return 1; // name already taken

    asprintf(&exec_cm, "INSERT INTO users VALUES(%u, \"%s\", \"%s\");",
      users_num++, member_info.name_.c_str(), member_info.key_word_.c_str());

    if (!exec_cm)
      throw std::bad_alloc();

    if (this->execute(exec_cm, NULL, NULL, &status) != SQLITE_OK)
    {
      server_db_internal_error ex = server_db_internal_error(status);
      sqlite3_free(status);
      free(exec_cm);
      throw ex;      
    }

    free(exec_cm);
    return 0;

  } 

  int16_t AccessParticipant(const Participant& member_info) const 
  {
    std::lock_guard<std::mutex> locker(db_mutex);

    char* exec_cm = nullptr; 
    asprintf(&exec_cm, "SELECT * FROM users WHERE pseudo = '%s' AND key = '%s'", 
      member_info.name_.c_str(), member_info.key_word_.c_str());
    if (!exec_cm)
      throw std::bad_alloc(); // TODO: 

    int count_record = 0;
    char* status = nullptr;

    if (DB::execute(
      exec_cm, &serverDB::CountRecords_callback, reinterpret_cast<void*>(&count_record), &status) != SQLITE_OK)
    {
      server_db_internal_error ex = server_db_internal_error(status);
      sqlite3_free(status);
      free(exec_cm);
      throw ex;    
    }

    free(exec_cm);
    if (count_record != 1) // equal 1 
      return 1;

    return 0;
  
  }
  
  ~serverDB() = default;
};
