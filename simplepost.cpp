/* Feel free to use this example code in any way
   you see fit (Public Domain) */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdint.h>
#include <microhttpd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <algorithm>
#include <iostream>
#include <fstream>
#include <string>
#include <set>
#include <type_traits>
#include <exception>
#include <thread>
#include <mutex>
#include <atomic>
#include <new> /* bad_alloc exception */
#include <forward_list>

#include "html_src/file_change.cpp"

#define WEBSERVERPORT    8888
#define POSTBUFFERSIZE   512
#define MAXNAMESIZE      20
#define MAXANSWERSIZE    512

// Chat configuration
/* max numbers of registered members */
#define MAXMEMBERSNUMBER 10
/* max numbers of current chaters */
#define MAXACTIVEMEMBERS 5


#define GET              0
#define POST             1

enum class BAD_REQUEST
{
  BAD_NAME,
  BAD_PASSWORD
};

const char *errorpage =
  "<html><body>This doesn't seem to be right.</body></html>";

#define SIGNUP_PAGE "html_src/sign_up.html"
#define SIGNIN_PAGE "html_src/sign_in.html"
#define SUCCESS "html_src/chat.html"
#define FAIL errorpage
#define COOKIE_NAME "session"

const char* NOT_FOUND_ERROR = "Resource not found!";


// with cokkies or with ban

struct Participant
{
// private:
  std::string name_;
  std::string key_word_;
  std::string info_;
public:
  Participant() = default;

  Participant(std::string name, std::string key_word, std::string info, bool registered = false) :
    name_(std::move(name)), key_word_(std::move(key_word)), info_(std::move(info)) {  }

  struct Comparer
  {
    bool operator()(const Participant& lhs, const Participant& rhs)
    {
      return lhs.name_.compare(rhs.name_) < 0 ? true : false;
    }
  };

  Participant(const Participant& that) :
    name_(that.name_), key_word_(that.key_word_), info_(that.info_) {  }

  const Participant& operator=(const Participant& that)
  {
    name_ = that.name_;
    key_word_ = that.key_word_;
    info_ = that.info_;
    return *this;
  }

  Participant(Participant&& that) noexcept : 
    name_(std::move(that.name_)), key_word_(std::move(that.key_word_)), info_(std::move(that.info_))
  {  }

  const Participant& operator=(Participant&& that) noexcept
  {
    name_ = std::move(that.name_);
    key_word_ = std::move(that.key_word_);
    info_ = std::move(that.info_);

    return *this;
  }

  friend std::ostream& operator<<(std::ostream&, const Participant&);

  ~Participant() = default;
};

std::ostream& operator<<(std::ostream& out, const Participant& participant)
{
  out << "name='" << participant.name_ << "'&key word='" << 
    participant.key_word_ << "'&info='" << participant.info_ << '\'';
  return out;

}

using DB = std::set<Participant, Participant::Comparer>;
DB partpants_list;
std::mutex db_mutex;

std::forward_list<struct Session*> sessionsList;

enum MHD_Result OpenNewConnForSignUp(unsigned short PORT);
std::thread signup_thread;

// TODO:
// we need to configure signup_thread
// about termination main server
// then we need to communicate two thread properly
// 1) future
// 2) atomic bool
// 3) condition_variable
std::atomic_bool continue_signup_webserver {true}; 

struct Session
{
  struct Participant chat_member;
  uint32_t STATUS_CODE;

  std::chrono::time_point<std::chrono::system_clock> start_;
  unsigned int rc;

  char sid[33];
  Session() = default;
  ~Session() = default;
};

struct connection_info_struct
{
  struct Session* session;
  struct MHD_PostProcessor *postprocessor; 
  uint8_t connectiontype;
};


void add_session_cookie (struct Session *session,
                    struct MHD_Response *response)
{
  char cstr[256];
  snprintf (cstr,
            sizeof (cstr),
            "%s=%s",
            COOKIE_NAME,
            session->sid);
  if (MHD_NO ==
      MHD_add_response_header (response,
                               MHD_HTTP_HEADER_SET_COOKIE,
                               cstr))
  {
    fprintf (stderr,
             "Failed to set session cookie header!\n");
  }
}

void panicTerminateDaemon(
  void* cls, const char* file, 
  unsigned int line_num, const char* info)
{
  fprintf(stderr, "in %s:%u error : %s", file, line_num, info);
  MHD_Daemon* daemon = (MHD_Daemon*) cls;
  if (!daemon)
    MHD_stop_daemon(daemon);
}

enum MHD_Result send_page(
  struct MHD_Connection *connection, struct Session* session,
  const char* page, enum MHD_ResponseMemoryMode MemoryMODE = MHD_RESPMEM_PERSISTENT)
{
  uint16_t STATUS_CODE = session->STATUS_CODE;
  enum MHD_Result ret;
  struct MHD_Response *response;

  if (strstr(page, ".html") != NULL)
  {
    struct stat file_buf;
    int file_desc;
    if( (file_desc = open(page, O_RDONLY)) != -1 &&
      fstat(file_desc, &file_buf) == 0)
    {
      response = MHD_create_response_from_fd(file_buf.st_size, file_desc);

      if (response == NULL)
      {
        fprintf(stderr, "MHD_create_response_from_fd() failed");
        close(file_desc);
        return MHD_NO;
      }

    } else 
    { 
      if (file_desc == EACCES)
      {
        response = MHD_create_response_from_buffer(strlen(NOT_FOUND_ERROR),
          (void*) NOT_FOUND_ERROR, MHD_RESPMEM_PERSISTENT);

        if (response == NULL)
        {
          fprintf(stderr, "MHD_create_response_from_buffer() failed");
          return MHD_NO;
        }

        STATUS_CODE = MHD_HTTP_NOT_FOUND;

      } else {
        perror("File open error");

        STATUS_CODE = MHD_HTTP_INTERNAL_SERVER_ERROR;
      }
    }
  } else 
  {
    response =
      MHD_create_response_from_buffer (strlen (page), (void *) page,
                                     MemoryMODE); // be careful with the MemoryMODE
    if (!response)
      return MHD_NO;
  }

  add_session_cookie(session, response);

  ret = MHD_queue_response (connection, STATUS_CODE, response);

  MHD_destroy_response (response);
  
  return ret;
}


void FillSignUp(Participant& chat_member, const char* key, const char* data)
{
  if (strcmp(key, "name") == 0)
  {
    chat_member.name_.assign(data);
  } else if (strcmp(key, "key word") == 0)
  {
    chat_member.key_word_.assign(data);
  } else if (strcmp(key, "info") == 0)
  {
    chat_member.info_.assign(data);
  }
}

void FillSignIn(Participant& chat_member, const char* key, const char* data)
{
  if (strcmp(key, "name") == 0)
  {
    chat_member.name_.assign(data);
  }
}

static enum MHD_Result iterate_post (
              void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
              const char *filename, const char *content_type,
              const char *transfer_encoding, const char *data, uint64_t off,
              size_t size)
{
  struct connection_info_struct *con_info = (struct connection_info_struct *)coninfo_cls;
  (void) kind;               /* Unused. Silent compiler warning. */
  (void) filename;           /* Unused. Silent compiler warning. */
  (void) content_type;       /* Unused. Silent compiler warning. */
  (void) transfer_encoding;  /* Unused. Silent compiler warning. */
  (void) off;                /* Unused. Silent compiler warning. */

  // !! java script should check size and format !! // 


  if (0 == strcmp (key, "name"))
  {
    if ((size > 0) && (size <= MAXNAMESIZE))
    {
      con_info->session->chat_member.name_.assign(data);
    } else 
    {
      con_info->session->STATUS_CODE = MHD_HTTP_BAD_REQUEST;
      return MHD_NO;
    }
  } else if (0 == strcmp(key, "key word"))
  {
    if ((size > 0) && (size <= MAXNAMESIZE))
    {
      con_info->session->chat_member.key_word_.assign(data);

    }else 
    {
      con_info->session->STATUS_CODE = MHD_HTTP_BAD_REQUEST;
      return MHD_NO;
    }
  } else if (0 == strcmp(key, "info") )
  {
    if ((size > 0))
    {
      con_info->session->chat_member.info_.assign(data);
    }

  } else 
  {
    con_info->session->STATUS_CODE = MHD_HTTP_BAD_REQUEST;
    return MHD_NO;
  }

  return MHD_YES;
} 

void request_completed (void *cls,
                            struct MHD_Connection *connection,
                            void **con_cls,
                            enum MHD_RequestTerminationCode toe)
{
  struct connection_info_struct* con_info = (struct connection_info_struct*)*con_cls;
  (void) cls;         /* Unused. Silent compiler warning. */
  (void) connection;  /* Unused. Silent compiler warning. */
  (void) toe;         /* Unused. Silent compiler warning. */

  if (con_info)
  {
    if (con_info->session)
      con_info->session->rc--;
    if (con_info->postprocessor)
    {
      MHD_destroy_post_processor (con_info->postprocessor);
      con_info->postprocessor = nullptr; // mindless
    }
    ::operator delete(con_info);
  }
}


uint32_t AddParticipant(const Participant&);
uint32_t AccessParticipant(const Participant&);
int Load_DB();


enum MHD_Result AccessConnection(void* cls,
  const struct sockaddr* addr, socklen_t addlen)
{
  
  return MHD_YES;
}

struct Session* get_session (struct MHD_Connection *connection)
{
  struct Session *ret;
  const char *cookie;

  cookie = MHD_lookup_connection_value (connection,
                                        MHD_COOKIE_KIND,
                                        COOKIE_NAME);
  if (cookie != NULL)
  {
    /* find existing session */
    auto found_iter = 
      std::find_if(sessionsList.begin(), sessionsList.end(), [cookie](const Session* session)
      {
        return strcmp(cookie, session->sid) == 0 ? true : false;
      });

    if (found_iter != sessionsList.end())
    {
      (*found_iter)->STATUS_CODE = MHD_HTTP_OK;
      return (*found_iter);
    }
  }

  /* create fresh session */
  ret = new (std::nothrow) Session;
  if (!ret)
  {
    fprintf (stderr, "ENOMEM");
    return nullptr;
  }
  /* not a super-secure way to generate a random session ID,
     but should do for a simple example... */
  snprintf (ret->sid,
            sizeof (ret->sid),
            "%X%X%X%X",
            (unsigned int) rand (),
            (unsigned int) rand (),
            (unsigned int) rand (),
            (unsigned int) rand ());

  ret->STATUS_CODE = MHD_HTTP_OK;
  ret->rc++;
  ret->start_ = std::chrono::system_clock::now();
  sessionsList.push_front(ret);
  return ret;
}

static enum MHD_Result answer_to_connection (
          void *cls, struct MHD_Connection *connection,
          const char *url, const char *method,
          const char *version, const char *upload_data,
          size_t *upload_data_size, void **con_cls)
{
  (void) cls;                          
  (void) version;          

  enum MHD_Result ret;
  struct Session* session = nullptr;
  struct connection_info_struct *con_info = (struct connection_info_struct *)*con_cls;

  if (!con_info)
  {
    struct connection_info_struct *con_info = reinterpret_cast<struct connection_info_struct*>(
      ::operator new(sizeof(struct connection_info_struct), std::nothrow));
    if (!con_info)
      return MHD_NO;

    con_info->session = nullptr;
    if (0 == strcmp (method, "POST"))
    {
      con_info->postprocessor =
        MHD_create_post_processor (connection, POSTBUFFERSIZE,
                                   iterate_post, (void *) con_info);

      if (NULL == con_info->postprocessor)
      {
        fprintf(stderr, "MHD_create_post_processor() failed: %s", strerror(errno));
        return MHD_NO;
      }

      con_info->connectiontype = POST;
    } else 
      con_info->connectiontype = GET;
    
    *con_cls = (void *) con_info;

    return MHD_YES;
  }

  if (!con_info->session)
  {
    con_info->session = get_session(connection);
    if (!con_info->session)
    {
      fprintf (stderr, "Failed to setup session for `%s'\n",
               url);
      return MHD_NO;
    }
  }

  session = con_info->session;
  session->start_ = std::chrono::system_clock::now();
  char page[64] = "html_src/sign_in.html";

  if (0 == strcmp (method, MHD_HTTP_METHOD_POST))
  {
    MHD_post_process (con_info->postprocessor, upload_data,
                        *upload_data_size);
    if (*upload_data_size != 0)
    {
      *upload_data_size = 0;
      return MHD_YES;
    }


    if (session->STATUS_CODE != MHD_HTTP_OK)
    {
      // wrong POST input data
      return MHD_NO;
    }

    MHD_destroy_post_processor(con_info->postprocessor);
    con_info->postprocessor = nullptr;

    method = MHD_HTTP_METHOD_GET;
    session->STATUS_CODE = 
      AccessParticipant(con_info->session->chat_member);
    
    if (session->STATUS_CODE != MHD_HTTP_OK)
    {
      std::string copied_name = HTML::CopyFileChangeTAGvalue("html_src/sign_in.html",
         {{"name", session->chat_member.name_.c_str()},
          {"key-word", session->chat_member.key_word_.c_str()}});
      
      if (session->STATUS_CODE == MHD_HTTP_UNAUTHORIZED)
        HTML::AddJSAlert(copied_name.c_str(), "Name or password is incorrect!");

      strncpy(page, copied_name.c_str(), sizeof(page));
    } else 
      strncpy(page, SUCCESS, sizeof(page));
  }

  if (0 == strcmp (method, MHD_HTTP_METHOD_GET))
  {
    return send_page(connection, session, page);
  }

  /* unsupported HTTP METHOD */
  return send_page (connection, session, errorpage);
}


void expire_sessions()
{
  std::chrono::time_point<std::chrono::system_clock> now =
    std::chrono::system_clock::now();

  auto prev_iter = sessionsList.cbefore_begin();
  for(auto iter = std::next(prev_iter); iter != sessionsList.cend(); )
  {
    if ((*iter)->start_ + std::chrono::hours{1} < now)
    {
      delete (*iter);
      iter = sessionsList.erase_after(prev_iter);
    } else 
    {
      ++iter; ++prev_iter;
    }
  }
}

struct Timer
{
  using clock = std::chrono::system_clock;
private:
  std::chrono::time_point<clock> start_;
  std::chrono::duration<int> duration_;
public:
  Timer(std::chrono::duration<int> duration) : 
    start_(std::chrono::system_clock::now()), duration_(duration) { }
  bool is_time_off() const noexcept
  {
    std::chrono::time_point<clock> now = 
      std::chrono::system_clock::now();
    return (start_ + duration_) > now;
  }

  ~Timer() = default;
};

int main()
{
  struct MHD_Daemon *daemon;

  if (Load_DB() == EXIT_FAILURE)
  {
    fprintf(stderr, "Load_DB failed");
    return EXIT_FAILURE;
  }

  daemon = MHD_start_daemon (MHD_USE_DEBUG,
                             WEBSERVERPORT, &AccessConnection, NULL,
                             &answer_to_connection, NULL,
                             MHD_OPTION_CONNECTION_TIMEOUT, 15u,
                             MHD_OPTION_NOTIFY_COMPLETED, &request_completed,
                             NULL, MHD_OPTION_END);
  if (NULL == daemon)
  {
    fprintf(stderr, "Daemon start failed!");
    return EXIT_FAILURE;
  }

  srand(time(NULL)); // seed;
  
  try
  {
    signup_thread = std::thread(&OpenNewConnForSignUp, 9000);
  } catch(const std::exception& ex) 
  {
    std::cerr << "std::thread() failed(" << ex.what() << ")"; 
    MHD_stop_daemon (daemon);
    return EXIT_FAILURE;
  }

  struct timeval tv;
  struct timeval *tvp;
  fd_set rs;
  fd_set ws;
  fd_set es;
  MHD_socket max;
  MHD_UNSIGNED_LONG_LONG mhd_timeout;

  Timer timer(std::chrono::seconds{50});
  while (timer.is_time_off())
  {
    expire_sessions ();
    max = 0;
    FD_ZERO (&rs);
    FD_ZERO (&ws);
    FD_ZERO (&es);
    if (MHD_YES != MHD_get_fdset (daemon, &rs, &ws, &es, &max))
      break; /* fatal internal error */
    if (MHD_get_timeout (daemon, &mhd_timeout) == MHD_YES)
    {
      tv.tv_sec = mhd_timeout / 1000;
      tv.tv_usec = (mhd_timeout - (tv.tv_sec * 1000)) * 1000;
      tvp = &tv;
    }
    else
      tvp = NULL;
    if (-1 == select (max + 1, &rs, &ws, &es, tvp))
    {
      if (EINTR != errno)
        fprintf (stderr,
                 "Aborting due to error during select: %s\n",
                 strerror (errno));
      break;
    }
    MHD_run (daemon);
  }

  for(auto iter = sessionsList.cbegin(); iter != sessionsList.cend(); ++iter)
  {
    delete *iter; // delete sessions;
  }

  if (signup_thread.joinable())
  {
    continue_signup_webserver = false;
    signup_thread.join();
  }

  MHD_stop_daemon (daemon);

  return 0;
}


uint32_t AddParticipant(const Participant& new_member)
{
  std::lock_guard<std::mutex> locker(db_mutex);
  if (new_member.key_word_.empty() || new_member.name_.empty())
    return MHD_HTTP_BAD_REQUEST;

  try
  {
    std::pair<DB::iterator, bool> inserted_elem =
     partpants_list.insert(new_member);
    if (!inserted_elem.second)
    {
      return MHD_HTTP_CONFLICT;
    }

    std::cout << "New member : '" << new_member.name_ << "'" << std::endl;

    std::ofstream DataBase ("users.txt", std::ios_base::out | std::ios_base::app);

    if (!DataBase.is_open())
    {
      std::cerr << "DataBase is not opened!";
      return MHD_HTTP_INTERNAL_SERVER_ERROR;
    }

    DataBase << new_member << std::endl;

    DataBase.close();

  } catch(const std::exception& ex) 
  {
    // stderr << "Not possible to registered new participant" << '(' << ex.what() << ')'; 
    return MHD_HTTP_INTERNAL_SERVER_ERROR; 
  }

  return MHD_HTTP_OK;
}

uint32_t AccessParticipant(const Participant& member)
{
  std::lock_guard<std::mutex> locker(db_mutex);
  DB::const_iterator iter = 
    partpants_list.find(member);

  if (iter != partpants_list.cend() && iter->key_word_ == member.key_word_)
  {
    return MHD_HTTP_OK;
  }
  
  return MHD_HTTP_UNAUTHORIZED;
}

int Load_DB()
{
  std::ifstream file_users_info ("users.txt", std::ios::in);
  if (!file_users_info.is_open())
  {
    return EXIT_FAILURE;
  }
  
  //name='...'&key word='...'&info='...'\n
  auto FillUserInfo = [](std::string& line,
    std::string& name, std::string& key_word, std::string& info)
  {
    char* check_available_ptr = NULL;
    // strtok(const_cast<char*>(line.c_str()));
    strtok(&line[0], "\'");

    if ((check_available_ptr = strtok(NULL, "\'")) == NULL)
      throw std::logic_error("DATABASE: empty name!");
    name.assign(check_available_ptr); strtok(NULL, "\'");

    if ((check_available_ptr = strtok(NULL, "\'")) == NULL)
      throw std::logic_error("DATABASE: empty key word!");
    key_word.assign(check_available_ptr); strtok(NULL, "\'");
    
    // if ((check_available_ptr = strtok(NULL, "\'")) != NULL)
    //   info.assign(check_available_ptr);
  };

  std::string line;
  std::string name, key_word, info;
  while(std::getline(file_users_info, line))
  {
    FillUserInfo(line, name, key_word, info);

    partpants_list.emplace(
      std::move(name), std::move(key_word), std::move(info));
  }

  file_users_info.close();

  return EXIT_SUCCESS;
}


enum MHD_Result answer_to_signup(
  void* cls, struct MHD_Connection* connection, 
  const char* url, const char* method, const char* version,
  const char* upload_data, size_t* upload_data_size, void** con_cls)
{
  
  enum MHD_Result ret;
  struct Session* session = nullptr;
  struct connection_info_struct *con_info = (struct connection_info_struct *)*con_cls;

  if (!con_info)
  {
    struct connection_info_struct *con_info = reinterpret_cast<struct connection_info_struct*>(
      ::operator new(sizeof(struct connection_info_struct), std::nothrow));
    if (!con_info)
      return MHD_NO;

    con_info->session = nullptr;
    if (0 == strcmp (method, "POST"))
    {
      con_info->postprocessor =
        MHD_create_post_processor (connection, POSTBUFFERSIZE,
                                   iterate_post, (void *) con_info);

      if (NULL == con_info->postprocessor)
      {
        fprintf(stderr, "MHD_create_post_processor() failed: %s", strerror(errno));
        return MHD_NO;
      }

      con_info->connectiontype = POST;
    } else 
      con_info->connectiontype = GET;
    
    *con_cls = (void *) con_info;

    return MHD_YES;
  }

  if (!con_info->session)
  {
    con_info->session = get_session(connection);
    if (!con_info->session)
    {
      fprintf (stderr, "Failed to setup session for `%s'\n",
               url);
      return MHD_NO;
    }
  }

  con_info->session->start_ = std::chrono::system_clock::now();
  con_info->session->STATUS_CODE = MHD_HTTP_OK;
  session = con_info->session;

  char page[64] = "html_src/sign_up.html";

  if (0 == strcmp (method, MHD_HTTP_METHOD_POST))
  {
    MHD_post_process (con_info->postprocessor, upload_data,
                        *upload_data_size);

    if (*upload_data_size != 0)
    {
      *upload_data_size = 0;
      return MHD_YES;
    }

    if (session->STATUS_CODE != MHD_HTTP_OK)
    {
      // wrong POST input data
      return MHD_NO;
    }

    MHD_destroy_post_processor(con_info->postprocessor);
    con_info->postprocessor = nullptr;

    method = MHD_HTTP_METHOD_GET;
    session->STATUS_CODE = 
      AddParticipant(con_info->session->chat_member);
    
    if (session->STATUS_CODE != MHD_HTTP_OK)
    {
      std::string name_copied = HTML::CopyFileChangeTAGvalue(page,
         {{"name", session->chat_member.name_.c_str()},
          {"key-word", session->chat_member.key_word_.c_str()},
          {"info", session->chat_member.info_.c_str()}});
      
      if (session->STATUS_CODE == MHD_HTTP_CONFLICT)
        HTML::AddJSAlert(name_copied.c_str(), "The name has already taken!");
      else if (session->STATUS_CODE == MHD_HTTP_INTERNAL_SERVER_ERROR)
        HTML::AddJSAlert(name_copied.c_str(), "Internal error!");
      else if (session->STATUS_CODE == MHD_HTTP_BAD_REQUEST)
        HTML::AddJSAlert(name_copied.c_str(), "Incorrect input data!");

      strncpy(page, name_copied.c_str(), sizeof(page));
    } else 
      strncpy(page, SUCCESS, sizeof(page));
  }

  if (0 == strcmp (method, MHD_HTTP_METHOD_GET))
  {
    return send_page(connection, session, page);
  }

  /* unsupported HTTP METHOD */
  return send_page (connection, session, errorpage);
}


enum MHD_Result OpenNewConnForSignUp(unsigned short PORT)
{
  struct MHD_Daemon* daemon;
  enum MHD_Result ret;

  daemon = MHD_start_daemon(
      MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG, PORT,
      NULL, NULL, &answer_to_signup, NULL, 
      MHD_OPTION_NOTIFY_COMPLETED, &request_completed,
      NULL, MHD_OPTION_END);

  if (daemon == NULL)
  {
    fprintf(stderr, "Daemon on port %d failed", static_cast<int>(PORT));
    return MHD_NO;
  }

  MHD_set_panic_func(&panicTerminateDaemon, (void*)daemon);

  while(continue_signup_webserver.load())
  {
    // waiting normal terminating
  }

  MHD_stop_daemon(daemon);

  // send future value about webserver is ready to detach

  return MHD_YES;
}