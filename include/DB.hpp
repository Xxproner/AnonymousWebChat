#ifndef DB_HPP_
#define DB_HPP_

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

  int open(const char* filename);

  DB(const DB&) = delete; // avoid careless copy operation 
  const DB& operator=(const DB&) = delete;

  int execute(const char* command, sqlite_callback f_callback, void* data, char** errormsg) const ;

  void close();

  virtual ~DB() noexcept; // ? virtual destructor
};



#endif // DB_HPP_