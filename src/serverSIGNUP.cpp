#include <libgen.h>

struct expand_details
{
private:
  static constexpr size_t hash_size = sizeof(size_t); 
  constexpr static const char* file_prefix = CONCAT(ABS_PATH, "static/");
  static constexpr size_t file_prefix_size = strlen(file_prefix);
  friend struct expand_withFILE_con_info_struct;
};

struct expand_withFILE_con_info_struct : public connection_info_struct
{
  char filename[expand_details::file_prefix_size + expand_details::hash_size * 8 + 4 + 1]; // prefix + hash + .jpg + '\0'
  std::ofstream icon_image;
  bool file_loaded = false;

  static void GenerateFileName(char* dest) 
  {
    // generate unique file name
  }

  static void GenerateFileNameUntilUniq(char* dest)
  {
    struct stat buf;
    GenerateFileName(dest);
    int file_exists = stat(dest, &buf);
    while (file_exists == 0)
    {
      GenerateFileName(dest);
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
      if (PossibleCharacters(data, size) != MHD_YES)
      {
        con_info->session->STATUS_CODE = MHD_HTTP_BAD_REQUEST;
        return MHD_NO;
      }

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
      if (PossibleCharacters(data, size) != MHD_YES)
      {
        con_info->session->STATUS_CODE = MHD_HTTP_BAD_REQUEST;
        return MHD_NO;
      }
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
          con_info->filename);
        con_info->icon_image.open(con_info->filename, std::ios_base::out | std::ios_base::binary);
        if (!con_info->icon_image.is_open())
        {
          throw std::runtime_error("Cannot download file!");
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
                                   &iterate_post_for_signup, (void *) con_info);

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
          {"key word", session->chat_member.key_word_.c_str()},
          {"info", session->chat_member.info_.c_str()}});

      HTML::AddJSAlert(name_copied.c_str(), "Wrong input data!");
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
      // CreateHTMLforParticipant(con_info);
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

/*int CreateHTMLforParticipant(const expand_withFILE_con_info_struct* con_info)
{
  char* html = nullptr;
  const Participant& participant = con_info->session->chat_member;
  char image_on_default[] = "def_image.jpg";

  char* filename = nullptr;
  if (con_info->file_loaded)
  {
    filename = basename(con_info->filename);
  }else 
    filename = strdup(image_on_default);

  if (!filename)
      throw std::runtime_error("Empty file name!");

  // name cannot contain specific symbols
  std::ofstream file = file.open(participant.name_ + ".html", std::ios_base::out | std::ios_base::binary);
   
  asprintf(&html, HTML::TEMPLATE_NEW_PAGE, filename, 
    participant.name_.c_str(), participant.info_.c_str());
  if (!html)
    throw std::bad_alloc();

  file << html;

  if (file.is_open())
    file.close();
  free(html);
  free(filename);
  return 0;
}*/

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