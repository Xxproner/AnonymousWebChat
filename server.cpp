/* Feel free to use this example code in any way
   you see fit (Public Domain) */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <microhttpd.h>

#include <algorithm>
#include <iostream>
#include <fstream>
#include <string>
#include <type_traits>
#include <exception>
#include <thread>
#include <atomic>
#include <new> /* std::bad_alloc exception */
#include <forward_list>
#include <functional> /* std::hash */

#include "html_src/file_change.cpp"
#include "serverDB.cpp"
#include "Participant.cpp"
#include "boost/lexical_cast.hpp"
using boost::lexical_cast;
using boost::bad_lexical_cast;

// #include "LyraArgs.hpp"

#define CONCAT(a, b) (a"" b) // For external macros

#define POSTBUFFERSIZE   512
#define MAXNAMESIZE      30
#define MAXANSWERSIZE    512

// Chat configuration
/* max numbers of registered members */
#define MAXMEMBERSNUMBER 10
/* max numbers of current chaters */
#define MAXACTIVEMEMBERS 5

#define GET              0
#define POST             1

const char *errorpage =
  "<html><body>This doesn't seem to be right.</body></html>";

#define SIGNUP_PAGE CONCAT(HTML_SRC_PATH, "sign_up.html")
#define SIGNIN_PAGE CONCAT(HTML_SRC_PATH, "sign_in.html")
#define SUCCESS CONCAT(HTML_SRC_PATH, "chat.html")

#define FAIL errorpage
#define COOKIE_NAME "session"

#define DENIED "<html><head><title>libmicrohttpd demo</title></head><body>Access denied</body></html>"
#define OPAQUE "11733b200778ce33060f31c9af70a870ba96ddd4"

const char* NOT_FOUND_ERROR = "<html><body>Not found!</body></html>";

// with cokkies or with ban

serverDB partpants_list;

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
  bool verificate;
  Session() = default;
  ~Session() = default;
};

struct connection_info_struct
{
  struct Session* session;
  struct MHD_PostProcessor *postprocessor; 
  uint8_t connectiontype;

  connection_info_struct() = default;
  ~connection_info_struct() = default;

};

struct expand_details
{
  static constexpr size_t hash_size = sizeof(size_t); 
  constexpr static const char* file_prefix = "../static/";
  static constexpr size_t file_prefix_size = strlen(file_prefix);
};

struct expand_withFILE_con_info_struct : public connection_info_struct
{
  char filename[expand_details::file_prefix_size + expand_details::hash_size * 8 + 4 + 1]; // prefix + hash + .jpg + '\0'
  std::ofstream icon_image;
  bool file_loaded = false;

  static void GenerateFileName(char* dest, const char* sed) 
  {
    if (!sed)
      throw std::runtime_error("Invalid sed!");

    std::string hash = std::to_string(std::hash<std::string>()(std::string{sed}));
    strcpy(dest, expand_details::file_prefix);
    hash.copy(dest + expand_details::file_prefix_size, expand_details::hash_size);
    strcpy(dest + expand_details::file_prefix_size + expand_details::hash_size, ".jpg"); // need '\0' at end? 
  }

  static void GenerateFileNameUntilUniq(char* dest, const char* sed)
  {
    struct stat buf;
    GenerateFileName(dest, sed);
    int file_exists = stat(dest, &buf);
    while (file_exists == 0)
    {
      GenerateFileName(dest, sed);
      file_exists = stat(dest, &buf);
    }

    if (file_exists != ENOENT)
      throw std::runtime_error("Internal error!");
  }

  expand_withFILE_con_info_struct() = default;

  ~expand_withFILE_con_info_struct()
  {
    if (icon_image.is_open())
      icon_image.close();
  }
};

int CreateHTMLforParticipant(const expand_withFILE_con_info_struct*);

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
  } else if (strcmp(key, "key word") == 0)
  {
    chat_member.key_word_.assign(data);
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
  } else 
  {
    con_info->session->STATUS_CODE = MHD_HTTP_BAD_REQUEST;
    return MHD_NO;
  }

  return MHD_YES;
} 

static enum MHD_Result iterate_post_for_signup(
              void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
              const char *filename, const char *content_type,
              const char *transfer_encoding, const char *data, uint64_t off,
              size_t size)
{
  expand_withFILE_con_info_struct *con_info = (expand_withFILE_con_info_struct *)coninfo_cls;
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

  } else if (0 == strcmp(key, "avatar_file"))
  {
    if (size > 0)
    {
      if (!con_info->icon_image.is_open())
      {
        expand_withFILE_con_info_struct::GenerateFileNameUntilUniq(
          con_info->filename, filename);
        con_info->icon_image.open(con_info->filename, std::ios_base::out | std::ios_base::binary);
        if (!con_info->icon_image.is_open())
        {
          std::string str_error = "Internal error! ";
          str_error.append(strerror(errno));
          throw std::runtime_error(str_error);
        }
        con_info->file_loaded = true;
      }

      con_info->icon_image.write(data, size);
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
  ret->verificate = false;
  sessionsList.push_front(ret);
  return ret;
}

enum MHD_Result DGVerificate(struct MHD_Connection* connection, struct Session* session)
{
  enum MHD_Result ret;
  struct MHD_Response* response = nullptr;
  const char *password = "FORELITE";
  const char *realm = "test@example.com";

  char *username = MHD_digest_auth_get_username (connection);
  if (username == NULL)
  {
    response = MHD_create_response_from_buffer(strlen (DENIED),
                           (void*)DENIED,
                           MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_auth_fail_response2 (connection,
                                         realm,
                                         OPAQUE,
                                         response,
                                         (int)MHD_NO,
                                         MHD_DIGEST_ALG_SHA256);
    MHD_destroy_response(response);
    return ret; // username is empty ?
  }

  ret = (MHD_Result)MHD_digest_auth_check2 (connection,
                                realm,
                    username,
                    password,
                    300,
                    MHD_DIGEST_ALG_SHA256);
  free(username);
  if ( (ret == MHD_INVALID_NONCE) ||
       (ret == MHD_NO) )
  {
    response = MHD_create_response_from_buffer(strlen (DENIED),
                           (void*)DENIED,
                           MHD_RESPMEM_PERSISTENT);
    if (NULL == response)
      return MHD_NO;
    ret = MHD_queue_auth_fail_response2 (connection,
                                         realm,
                     OPAQUE,
                     response,
                     (ret == MHD_INVALID_NONCE) ? MHD_YES : MHD_NO,
                                         MHD_DIGEST_ALG_SHA256);
    MHD_destroy_response(response);
    return ret;
  }

  session->verificate = true;
  return ret ;
}

static enum MHD_Result answer_to_connection (
          void *cls, struct MHD_Connection *connection,
          const char *url, const char *method,
          const char *version, const char *upload_data,
          size_t *upload_data_size, void **con_cls)
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

  session = con_info->session;
  session->start_ = std::chrono::system_clock::now();

  const char* http_content_type = MHD_lookup_connection_value(
    connection, MHD_HEADER_KIND, "Content-Type");

  if (http_content_type && 
      strcasecmp(http_content_type, "application/json") == 0)
  {
    const char* bad_request = 
      "json is not keep this server. We are busy on it!";
    session->STATUS_CODE = MHD_HTTP_BAD_REQUEST;
    return send_page(connection, session, bad_request, MHD_RESPMEM_MUST_COPY);
  }


  // if (!session->verificate)
  //   if (DGVerificate(connection, session) == MHD_NO)
  //     return MHD_NO;

  // if (!session->verificate)
  //   return MHD_YES; // not verificate

  char page[64] = SIGNIN_PAGE;
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
      std::string name_copied = HTML::CopyFileChangeTAGvalue(page,
         {{"name", session->chat_member.name_.c_str()},
          {"key-word", session->chat_member.key_word_.c_str()}});

      HTML::AddJSAlert(name_copied.c_str(), "Wrong input data!");
      session->STATUS_CODE = MHD_HTTP_BAD_REQUEST;
      return send_page(connection, session, name_copied.c_str());
    }

    MHD_destroy_post_processor(con_info->postprocessor);
    con_info->postprocessor = nullptr;

    method = MHD_HTTP_METHOD_GET;

    int db_code_exec = 0;
    try
    {
      db_code_exec = 
        partpants_list.AccessParticipant(con_info->session->chat_member);
    } catch(const std::exception& ex)
    {
      std::cerr << "AccessParticipant() failed! " << 
        ex.what() << std::endl;
      
      return MHD_NO;
    }


    if (db_code_exec != 0)
    {
      std::string copied_name = HTML::CopyFileChangeTAGvalue(SIGNIN_PAGE,
         {{"name", session->chat_member.name_.c_str()},
          {"key-word", session->chat_member.key_word_.c_str()}});
      
      session->STATUS_CODE = MHD_HTTP_UNAUTHORIZED;
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

template <typename TLiteral>
struct Timer
{
  using clock = std::chrono::system_clock;
private:
  std::chrono::time_point<clock> start_;
  TLiteral duration_;
public:
  Timer(TLiteral duration) : 
    start_(std::chrono::system_clock::now()), duration_(duration) { }
  bool is_time_off() const noexcept
  {
    std::chrono::time_point<clock> now = 
      std::chrono::system_clock::now();
    return (start_ + duration_) > now;
  }

  ~Timer() = default;
};

int main(int argc, char* argv[])
{
  auto PrintHelp = []()
  {
    printf("./main\n");
    printf("-t [time server work (s/m/h)]. Default value is inf\n");
    printf("-p [port]. Default port is `8888'\n");
    printf("--debug [debug flag]. Default is disable\n");
    printf("--A [MHD_AcceptPolicyCallback arg]. Default value is `NULL'\n");
    printf("--H [MHD_AccessHandlerCallback arg]. Default value is `NULL'\n");
    printf("-------------------------Configuration--------------------------\n");
  };

  char time_literal = 's';
  size_t duration = -1;
  unsigned short WEBSERVERPORT = 8888;
  bool debug = false;
  char* accept_arg = nullptr;
  char* handle_arg = nullptr;

  char opt;
  while ((opt = getopt(argc, argv, ":t:p:dA:H:")) != -1)
  {
    switch (opt)
    {
      case 't': 
        time_literal = optarg[strlen(optarg) - 1];
        duration = static_cast<size_t>(atoi(optarg));
        break;
      case 'p':
        WEBSERVERPORT = lexical_cast<unsigned short>(optarg);
        break;
      case 'd':
        debug = true;
        break;
      case 'A':
        accept_arg = strdup(optarg);
        if (!accept_arg)
          throw std::bad_alloc();
        break;
      case 'H':
        handle_arg = strdup(optarg);
        if (!handle_arg)
          throw std::bad_alloc();
        break;
      case ':':
      case '?':
        PrintHelp();
        return 1;
    }
  }

  // lyra::args(argc, argv);

  // if (!args.begin())
    // PrintHelp();

  struct MHD_Daemon *daemon;

  if (partpants_list.open(CONCAT(DB_PATH, "users.db")))
  {
    std::cerr << "DB open() failed!\n";
    return EXIT_FAILURE; 
  } // else SUCCESS

  daemon = MHD_start_daemon (MHD_USE_DEBUG,
                             WEBSERVERPORT, &AccessConnection, accept_arg,
                             &answer_to_connection, handle_arg,
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
    // signup_thread = std::thread(&OpenNewConnForSignUp, 9000);
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

  Timer<std::chrono::seconds> timer(std::chrono::seconds{40});
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
  if (accept_arg)
    free(accept_arg); 
  if (handle_arg)
    free(handle_arg);
  
  return 0;
}

// in general, we need other iterate post

enum MHD_Result answer_to_signup(
  void* cls, struct MHD_Connection* connection, 
  const char* url, const char* method, const char* version,
  const char* upload_data, size_t* upload_data_size, void** con_cls)
{
  
  enum MHD_Result ret;
  struct Session* session = nullptr;
  expand_withFILE_con_info_struct *con_info = (expand_withFILE_con_info_struct *)*con_cls;

  if (!con_info)
  {
    expand_withFILE_con_info_struct *con_info = reinterpret_cast<expand_withFILE_con_info_struct*>(
      ::operator new(sizeof(expand_withFILE_con_info_struct), std::nothrow));
    if (!con_info)
      return MHD_NO;

    con_info->session = nullptr;
    if (0 == strcmp (method, "POST"))
    {
      con_info->postprocessor =
        MHD_create_post_processor (connection, POSTBUFFERSIZE,
                                   iterate_post_for_signup, (void *) con_info);

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

  char page[64] = SIGNUP_PAGE;

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
      std::string name_copied = HTML::CopyFileChangeTAGvalue(page,
         {{"name", session->chat_member.name_.c_str()},
          {"key-word", session->chat_member.key_word_.c_str()},
          {"info", session->chat_member.info_.c_str()}});

      HTML::AddJSAlert(name_copied.c_str(), "Wrong input data!");
      session->STATUS_CODE = MHD_HTTP_BAD_REQUEST;
      return send_page(connection, session, name_copied.c_str());
    }

    MHD_destroy_post_processor(con_info->postprocessor);
    con_info->postprocessor = nullptr;

    method = MHD_HTTP_METHOD_GET;

    int db_code_exec = 0; 
    try
    {
      db_code_exec =       
        partpants_list.AddParticipant(con_info->session->chat_member);
    } catch(const std::exception& ex)
    {
      // send internal error code to client;
      std::cerr << "AddParticipant() failed! " << 
        ex.what() << std::endl;

      session->STATUS_CODE = MHD_HTTP_INTERNAL_SERVER_ERROR;
      return send_page(connection, session, errorpage);
    }
    
    if (db_code_exec != 0) // from data base 
    {
      std::string name_copied = HTML::CopyFileChangeTAGvalue(page,
         {{"name", session->chat_member.name_.c_str()},
          {"key-word", session->chat_member.key_word_.c_str()},
          {"info", session->chat_member.info_.c_str()}});

      HTML::AddJSAlert(name_copied.c_str(), "The name has already taken!");
      session->STATUS_CODE = MHD_HTTP_CONFLICT;
      strncpy(page, name_copied.c_str(), sizeof(page));
    } else 
    {
      CreateHTMLforParticipant(con_info);
      // redaction success page
      strncpy(page, SUCCESS, sizeof(page));
    }
  }

  if (0 == strcmp (method, MHD_HTTP_METHOD_GET))
  {
    return send_page(connection, session, page);
  }

  /* unsupported HTTP METHOD */
  return send_page (connection, session, errorpage);
}

int CreateHTMLforParticipant(const expand_withFILE_con_info_struct* con_info)
{
  char* html = nullptr;
  const Participant& participant = con_info->session->chat_member;
  char image_on_default[] = "def_image.jpg";

  char* filename = nullptr;
  std::ofstream file;
  if (con_info->file_loaded)
  {
    filename = strdup(con_info->filename);
    file.open(filename, std::ios_base::out | std::ios_base::binary);
  }
  else 
    filename = strdup("def_image.jpg");

  if (!filename)
      throw std::bad_alloc();

  asprintf(&html, HTML::TEMPLATE_NEW_PAGE, filename, participant.name_.c_str(), 
    participant.info_.c_str());
  if (!html)
    throw std::bad_alloc();

  file << html;

  if (file.is_open())
    file.close();
  free(filename);
  return 0;
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