#include "Server.hpp"


int main()
{
	Server registration_server(
		  8080, &FilterIP, nullptr, 
      &answer_to_connection, nullptr,
      );
	

	return 0;
}

enum MHD_Result AnswerForConnection(
          void *cls, struct MHD_Connection *connection,
          const char *url, const char *method,
          const char *version, const char *upload_data,
          size_t *upload_data_size, void **con_cls)
{
  (void) cls;

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
      "<html><body>json is not keep this server. We are busy on it!</html></body>";
    session->STATUS_CODE = MHD_HTTP_BAD_REQUEST;
    return send_page(connection, session, bad_request, MHD_RESPMEM_MUST_COPY);
  }

  // if (!session->verificate)
  // {
  //   if (DGVerificate(connection) == MHD_YES)
  //   {
  //     session->verificate = true;
  //   }else {
  //       return MHD_NO;
  //   }
  // }


  char page[64] = SIGNIN_PAGE;
  if (0 == strcmp (method, MHD_HTTP_METHOD_POST))
  {
    // con_info->session->STATUS_CODE = MHD_HTTP_OK;

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
    return send_page(connection, session, page);

  /* unsupported HTTP METHOD */
  session->STATUS_CODE = MHD_HTTP_BAD_REQUEST;
  return send_page (connection, session, errorpage);
}

MHD_Result iterate_post (
              void *coninfo_cls
              , enum MHD_ValueKind kind
              , const char *key
              , const char *filename
              , const char *content_type
              , const char *transfer_encoding
              , const char *data
              , uint64_t off, size_t size)
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
  } else 
  {
    con_info->session->STATUS_CODE = MHD_HTTP_BAD_REQUEST;
    return MHD_NO;
  }

  return MHD_YES;
} 


enum MHD_Result BasicVerificate(struct MHD_Connection* connection)
{
  enum MHD_Result ret;
  struct MHD_Response* response = nullptr;
  char *user = nullptr;
  char *pass = nullptr;
  int fail;
  
  user = MHD_basic_auth_get_username_password (connection,
                                               &pass);

  std::string hashing_password = SHA256(pass);
  fail = ( (NULL == user) ||
           (0 != strcmp (hashing_password.c_str(), "d0949375b349696a1d9f14b2a9f119b396bd877ba0541f897a65557b8efe9305")));
  
  if (NULL != user)
    MHD_free (user);
  if (NULL != pass)
    MHD_free (pass);
  if (fail)
  {
    // const char *page = "<html><body>Go away.</body></html>";
    response =
      MHD_create_response_from_buffer (strlen (page), (void *) page,
                                       MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_basic_auth_fail_response (connection,
                                              "my realm",
                                              response);
    MHD_destroy_response(response);

    return MHD_NO;
  }

  return MHD_YES;
}

enum MHD_Result DGVerificate(struct MHD_Connection* connection)
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
    return MHD_NO;
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
    return MHD_NO;
  }

  return MHD_YES;
}

enum MHD_Result FilterIP(void *cls, const struct sockaddr * addr, socklen_t addrlen)
{

}