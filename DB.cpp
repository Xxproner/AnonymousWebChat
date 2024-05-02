
/* SQLite library */
#include <sqlite3.h>

/* STANDART C++ LIBRARY */
#include <string>
#include <stdexcept>

class DB
{
  typedef int (*sqlite_callback)(void*, int, char**, char**);
protected:
  sqlite3* db;
public:
  DB() = default;

  int open(const char* filename) 
  {
    return sqlite3_open(filename, &db);
  }

  DB(const DB&) = delete; // avoid careless copy operation 
  const DB& operator=(const DB&) = delete;

  int execute(const char* command, sqlite_callback f_callback, void* data, char** errormsg) const 
  {
    if (!db)
      throw std::runtime_error("Error execute DB! NULL DB");
    return sqlite3_exec(db, command, f_callback, data, errormsg);
  }

  ~DB() noexcept // ? virtual destructor
  {
    if (db)
      sqlite3_close(db);
  }

};


