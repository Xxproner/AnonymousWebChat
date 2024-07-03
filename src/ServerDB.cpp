#include "ServerDB.hpp"

#ifdef DEBUG
    #include <iostream>
#endif

int16_t serverDB::open(const char* filename)
{
  // if table does not already exist for some reason
  int exec_code = sqlite3_open(filename, &db);
  if (exec_code)
    return DB_OPN_ERROR;

  const char* create_table_cm = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, pseudo VARCHAR(30), key VARCHAR(30));";
  char* status = nullptr;
  if (this->execute(create_table_cm, NULL, NULL, &status) != SQLITE_OK)
  {
#ifdef DEBUG 
    std::cerr << "DB error: " << status << '\n';
#endif
    sqlite3_free(status);
    return DB_EXEC_ERROR;
  }

  const char* count_cm = "SELECT COUNT(*) AS 'NUM' FROM users";
  if (this->execute(count_cm, &serverDB::CountRecords_inTable, reinterpret_cast<void*>(&users_num), &status) != SQLITE_OK)
  {
#ifdef DEBUG 
    std::cerr << "DB error: " << status << '\n';
#endif
    sqlite3_free(status);
    return DB_EXEC_ERROR;
  }

  users_num += 1; // next id

  return DB_OK;
}

int16_t serverDB::AddParticipant(const Participant& member_info) 
{
  std::lock_guard<std::mutex> locker(db_mutex);
  
  char* exec_cm = nullptr;
  asprintf(&exec_cm, "SELECT * FROM users WHERE pseudo = \"%s\"", member_info.name.c_str());
  if (!exec_cm)
    return DB_UNSPEC_ERROR;

  int count_record = 0;
  char* status = nullptr;

  if (this->execute(
    exec_cm, &serverDB::CountRecords_callback, reinterpret_cast<void*>(&count_record), &status) != SQLITE_OK) // ? error
  {
#ifdef DEBUG 
    std::cerr << "DB error: " << status << '\n';
#endif
    sqlite3_free(status);
    free(exec_cm);
    return DB_EXEC_ERROR;
  }

  free(exec_cm); exec_cm = nullptr;
  if (count_record != 0) // equal 1 
    return DB_NAME_BUSY; // name already taken

  asprintf(&exec_cm, "INSERT INTO users VALUES(%u, \"%s\", \"%s\");",
    users_num++, member_info.name.c_str(), member_info.password.c_str());

  if (!exec_cm)
    return DB_UNSPEC_ERROR;

  if (this->execute(exec_cm, NULL, NULL, &status) != SQLITE_OK)
  {
#ifdef DEBUG 
    std::cerr << "DB error: " << status << '\n';
#endif
    sqlite3_free(status);
    free(exec_cm);
    return DB_EXEC_ERROR;
  }

  free(exec_cm);
  return DB_OK;

} 

int16_t serverDB::AccessParticipant(const Participant& member_info) const 
{
  std::lock_guard<std::mutex> locker(db_mutex);

  char* exec_cm = nullptr; 
  asprintf(&exec_cm, "SELECT * FROM users WHERE pseudo = '%s' AND key = '%s'", 
    member_info.name.c_str(), member_info.password.c_str());
  if (!exec_cm)
    return DB_UNSPEC_ERROR;

  int count_record = 0;
  char* status = nullptr;

  if (DB::execute(
    exec_cm, &serverDB::CountRecords_callback, reinterpret_cast<void*>(&count_record), &status) != SQLITE_OK)
  {
#ifdef DEBUG 
    std::cerr << "DB error: " << status << '\n';
#endif
    sqlite3_free(status);
    free(exec_cm);
    return DB_EXEC_ERROR;
  }

  free(exec_cm);
  if (count_record != 1) // equal 1 
    return DB_ACCS_DENIED;

  return DB_OK;

}

