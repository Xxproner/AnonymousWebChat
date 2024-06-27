#include "Server.hpp"

#include <time.h>

#include "sha256.h"

#include <iostream>
#include <algorithm>
#include <chrono>
#include <cassert>

#warning "ServerDB is public member!"

Server::Session* Server::GetSession (struct MHD_Connection *connection)
{
	struct Session *ret;
	const char *cookie;

	cookie = MHD_lookup_connection_value (connection,
										MHD_COOKIE_KIND,
										"Cookie");
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
			// (*found_iter)->STATUS_CODE = MHD_HTTP_OK;
			return (*found_iter);
		}
	}

	/* create fresh session */
	ret = new (std::nothrow) Session;
	if (!ret)
	{
		fprintf (stderr, "Server::GetSession(): allocate error!");
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

void Server::ExpireSession() noexcept
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


MHD_Result Server::ReplyToOptionsMethod(MHD_Connection* connection)
{
	MHD_Response* response = MHD_create_response_from_buffer(strlen(Server::EMPTY_RESPONSE), 
		(void*)EMPTY_RESPONSE, MHD_RESPMEM_PERSISTENT);
	if (response == NULL)
	{
		std::cerr << "ReplyToOptionsMethod(): create response error!";
		return MHD_NO;
	}

	std::string list_allow_methods;
	list_allow_methods.reserve(30);
	list_allow_methods.append("GET").append(", POST").append(", OPTIONS");

	long unsigned codes = 0;
	codes |= (MHD_add_response_header(response, "Allow", list_allow_methods.c_str()) 		== MHD_NO) 	<< 0;
	codes |= (MHD_add_response_header(response, "Cache-control", "public, max-age=172800") 	== MHD_NO) 	<< 1;
	codes |= (MHD_add_response_header(response, "Server", Server::MY_SERVER)				== MHD_NO) 	<< 2;
	codes |= (MHD_add_response_header(response, "Access-Control-Allow-Origin", "*") 		== MHD_NO) 	<< 3;

	if (codes != 0)
	{
		int code_number = 0;
		while (codes != 0)
		{
			bool code = codes & 1U; 
			if (code)
				std::cerr << code_number << " header is not set!\n";
			++code_number;
			codes >>= 1;
		}
	}

	// Access-Control-Allow-Origin: *
	// Access-Control-Allow-Origin: https://foo.bar.org
	// Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE
	// Access-Control-Allow-Headers: X-Requested-With

	MHD_Result ret = MHD_queue_response(connection, HTTP::HttpStatusCode::NoContent, response);

	MHD_destroy_response(response);
	return ret;
}

const std::string Server::HashBasicAuthCode = 
		"d0949375b349696a1d9f14b2a9f119b396bd877ba0541f897a65557b8efe9305";
// de facto Basic Authorization
MHD_Result Server::BasicVerificate(struct MHD_Connection* connection)
{	
	auto SendUnauthorized = [connection]() -> void{
		MHD_Response* response = MHD_create_response_from_buffer(strlen(Server::DENIED),
			(void*)Server::DENIED, MHD_RESPMEM_PERSISTENT); //  MHD_RESPMEM_MUST_COPY

		if (response == NULL)
		{
			std::cerr << "BasicVerificate(): create response error!\n";
			return ;
		}

		MHD_Result ret = MHD_queue_basic_auth_fail_response(connection, "realm", response);
		if (ret == MHD_NO)
		{
			std::cerr << "BasicVerificate(): queue response error!\n";
		}

		MHD_destroy_response(response);
	};

	char *user = nullptr;
	char *pass = nullptr;
	bool fail;
	
	user = MHD_basic_auth_get_username_password(connection, &pass);

	fail = ( (NULL == user) || (NULL == pass) ||
					 (HashBasicAuthCode != SHA256::hashString(pass)));
	
	if (NULL != user)
		MHD_free (user);
	if (NULL != pass)
		MHD_free (pass);
	if (fail)
	{
		SendUnauthorized();
		return MHD_NO;
	}

	return MHD_YES;
}

// de facto Digest Authorization
MHD_Result Server::DGVerificate(struct MHD_Connection* connection)
{
	enum MHD_Result ret;
	struct MHD_Response* response = nullptr;
	const char *password = "FORELITE";
	const char *realm = "auth_users@example.com";

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

	ret = (MHD_Result) MHD_digest_auth_check2(connection,
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

// template <typename STR>
// int RegisterResource(int method, STR url, 
// 	ResFunc func)
// {
// 	static_assert(std::is_same<STR, std::string_view> || 
// 		std::is_same<STR, std::string     >);

// 	auto emplace_result = resources.emplace(
// 		method, std::move(url), func);
// 	if (!emplace_result.second)
// 	{
// 		std::cerr << "RegisterResource() error:" <<  
// 			" resource is not registered. I don't know why(\n";
// 		return -1;
// 	}

// 	return 0;
// }

MHD_Result Server::ReplyToConnection(
					void *cls, struct MHD_Connection *connection,
					const char *url, const char *method,
					const char *version, const char *upload_data,
					size_t *upload_data_size, void **con_cls)
{
	Server* back_server = *reinterpret_cast<Server**>(cls); 

	if (!back_server)
	{
		std::cerr << __FUNCTION__ << " error: Server pointer is null!\n";
		return MHD_NO;
	}

	enum MHD_Result ret;
	// Session* session = nullptr;
	ConnectionInfo *con_info = reinterpret_cast<ConnectionInfo*>(*con_cls);

	if (!con_info)
	{
		try
		{
			if (strcmp (method, MHD_HTTP_METHOD_POST) == 0) // if POST method
			{
				// MHD library parser of post data
				// only above two content-type
				const char* content_type = MHD_lookup_connection_value(
					connection, MHD_HEADER_KIND, "Content-Type");
				if (content_type == NULL)
				{
					session->STATUS_CODE = MHD_HTTP_BAD_REQUEST;
					return SendPage(connection, session, Server::ERROR_PAGE, MHD_RESPMEM_PERSISTENT);
				}
				
				if (strcasecmp(content_type, MHD_HTTP_POST_ENCODING_FORM_URLENCODED) == 0 ||
					strcasecmp(content_type, MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA) == 0)
				{
					// MHD post process
					con_info = new Server::ConnectionInfo(url, connection, 
						Server::POSTBUFFERSIZE, &IteratePostData);
				} else 
				{
					con_info = new Server::ConnectionInfo(url, connection, 
						Server::POSTBUFFERSIZE, &PostDataParser);
				}
			} else 
			{
				con_info = new Server::ConnectionInfo(url);
			}

			*con_cls = (void *) con_info;
		} catch(...) // dont interested what exception we get
		{
			return MHD_NO;
		}

		return MHD_YES;
	}

	// if (!con_info->session)
	// {
	// 	con_info->session = back_server->GetSession(connection);
	// 	if (!con_info->session)
	// 	{
	// 		std::cerr << __FUNCTION__ << "Failed to setup session for `%s" << url << "'\n";
	// 		return MHD_NO;
	// 	}
	// }

	// session = con_info->session;
	// session->start_ = std::chrono::system_clock::now();

	// available methods
	if (strcmp(method, MHD_HTTP_METHOD_POST) != 0 && 
		strcmp(method, MHD_HTTP_METHOD_GET) != 0)
	{
		if (strcmp(method, MHD_HTTP_METHOD_OPTIONS) == 0)
		{
			return back_server->ReplyToOptionsMethod(connection);
		} else 
		{
			session->STATUS_CODE = HTTP::HttpStatusCode::MethodNotAllowed;
			return SendPage(connection, session, Server::ERROR_PAGE, MHD_RESPMEM_PERSISTENT);
		}
	}

	// authorization
	if (!session->verificate)
	{
		if (Server::BasicVerificate(connection) == MHD_YES)
		// if (Server::DGVerificate(connection) == MHD_YES)
		{
			session->verificate = true;
		}
	}

	// char page[64]; 
	// memcpy(page, Server::SIGNIN_PAGE, strlen(Server::SIGNIN_PAGE) + 1);

	if (0 == strcmp (method, MHD_HTTP_METHOD_POST))
	{
		if (*upload_data_size != 0)
		{
			con_info->PostProcess(upload_data, *upload_data_size);		
			
			*upload_data_size = 0;	
			return MHD_YES;
		}

		if (strcmp(url, "/sign_up.html") == 0)
		{
			SignUp();
		} else if (strcmp(url, "/sign_in.html") == 0)
		{
			SignIn();
		}
	} else if (0 == strcmp (method, MHD_HTTP_METHOD_GET))
	{
		return SendPage(connection, session, url); // <--- url
	}

	std::cerr << "Unexpected terminating connection!\n";
	return MHD_YES;
}


Server::~Server() noexcept
{
	partpants_list.close();

	auto prev_iter = sessionsList.cbefore_begin();
	for(auto iter = std::next(prev_iter); iter != sessionsList.cend(); )
	{
		delete (*iter);
		iter = sessionsList.erase_after(prev_iter);
	}

}

static std::string operator ""_s(const char* str, long unsigned int length)
{
	return std::string(str);
}

char* strdupxx(std::string_view str)
{
	size_t str_len = str.length();
	char* new_str = new char[str_len];
	std::char_traits<char>::copy(new_str, str.data(), str_len);
	return new_str;
}

// =========================================================
// ==================== ConnectionInfo =====================
// =========================================================
Server::ConnectionInfo::ConnectionInfo(const char* _url) 
	: session(nullptr)
	, postprocessor(nullptr)
	, connectiontype(HTTP::GET)
	, url(nullptr)
	, parser(nullptr)
{
	assert(_url != NULL && "url is NULL!");
	url = strdupxx(_url);
}


Server::ConnectionInfo::ConnectionInfo(const char* _url,
								MHD_Connection* connection, 
								size_t post_buffer_size,
								MHD_PostDataIterator post_data_iterator)
	: session(nullptr)
	, postprocessor(nullptr)
	, connectiontype(HTTP::POST)
	, url(nullptr) 
	, parser(nullptr)
{
	assert(_url != NULL && "url is NULL!");
	url = strdupxx(_url);

	/* postprocessor should return code, it is internal error or bad request */
	postprocessor =
		MHD_create_post_processor(connection, post_buffer_size,
								post_data_iterator, reinterpret_cast<void*>(this));

	if (postprocessor == NULL)
		throw std::runtime_error("Post processor create error!");
}

Server::ConnectionInfo::ConnectionInfo(
								const char* _url,
								MHD_Connection* conn,
								size_t post_buffer_size,
								ParsePostData _parser,
								void* cls)
	: session(nullptr)
	, postprocessor(nullptr)
	, connectiontype(HTTP::POST)
	, url(nullptr)
	, parser(nullptr)
{
	assert(_url != NULL && "url is NULL!");
	
	url = strdupxx(_url);

	parser = new SimplePostProcessor(conn, post_buffer_size, _parser, cls);
}

MHD_Result Server::ConnectionInfo::PostProcess(
								const char* data,
								size_t size)
{
	if (parser)
		return parser->parser(parser->conn, data, size);

	return MHD_post_process(postprocessor, data, size);
}

Server::ConnectionInfo::~ConnectionInfo()
{
	if (postprocessor)
		MHD_destroy_post_processor(postprocessor);
	else if (parser)
		delete parser;

	if (url)
		delete[] url;

}
// =========================================================
// ================= end ConnectionInfo ====================
// =========================================================


// =========================================================
// ================== SimplePostProcessor ==================
// =========================================================
SimplePostProcessor::SimplePostProcessor(
								MHD_Connection* _conn,
								size_t _post_buffer_size,
								ParsePostData _parser,
								void* _cls)
	: parser(_parser)
	, post_buffer_size(_post_buffer_size)
	, cls(_cls)
{
	assert(_parser != NULL && "ParsePostData is NULL!");
	assert(_conn != NULL && "MHD_Connection is NULL!");

	buffer = new char[_post_buffer_size];
}


SimplePostProcessor::~SimplePostProcessor()
{
	delete[] buffer;
}
// =========================================================
// ================== ending SimplePostProcessor ===========
// =========================================================


// =========================================================
// ================== ResourceHash =========================
// =========================================================
static void CeaserAlgo(std::string& str, int step)
{
#warning "Overflow is possible"
	std::transform(str.cbegin(), str.cend(), str.begin(),
		[step](char ch){ return ch += step; });
}

size_t Server::ResourceHash::operator()(
	const std::pair<int, std::string>& instance)
{
	std::hash<std::string> hsa;

	std::string copy_string = instance.second;
	CeaserAlgo(copy_string, instance.first);

	return hsa(copy_string);
}
// =========================================================
// ================== ending ResourceHash ==================
// =========================================================


// #include "serverSIGNUP.cpp"
