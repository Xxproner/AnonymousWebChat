#include "DB.hpp"

int DB::open(const char* filename) 
{
  return sqlite3_open(filename, &db);
}

int DB::execute(const char* command, sqlite_callback f_callback, void* data, char** errormsg) const 
{
  if (!db)
    throw std::runtime_error("Error execute DB! NULL DB");
  return sqlite3_exec(db, command, f_callback, data, errormsg);
}

void DB::close()
{
  if (db)
  {
    sqlite3_close(db);
    db = nullptr;
  }
}

DB::~DB() noexcept // ? virtual destructor
{
  if (db)
  {
    sqlite3_close(db);
    db = nullptr;
  }
}