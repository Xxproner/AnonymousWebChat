/* Feel free to use this example code in any way
	 you see fit (Public Domain) */

#include <sys/stat.h>
#include <fcntl.h>

#include <iostream>
#include <string>
#include <thread>
#include <algorithm>
#include <functional>
#include <cassert>


#include "boost/lexical_cast.hpp"
#include "boost/json/json.hpp"


#include "Server.hpp"
#include "htmlUtils.hpp"
#include "SessionList.hpp"

using boost::lexical_cast;
using boost::bad_lexical_cast;
using Resource = Server::Resource;

using namespace std::placeholders;

#if 1
unsigned constexpr chash(char const *input) {
	return *input ?
		static_cast<unsigned int>(*input) + 33 * chash(input + 1) :
		5381;
}

#	define SWITCH(str) switch(chash(str))
#	define CASE(str) case(chash(str))
#	define DEFAULT default
#endif

typedef uint16_t http_code_t ;

// template <typename TLiteral>
// struct Timer
// {
// 	using clock = std::chrono::system_clock;
// private:
// 	std::chrono::time_point<clock> start_;
// 	TLiteral duration_;
// public:
// 	Timer(TLiteral duration) : 
// 		start_(std::chrono::system_clock::now()), duration_(duration) { }
// 	bool is_time_off() const noexcept
// 	{
// 		std::chrono::time_point<clock> now = 
// 			std::chrono::system_clock::now();
// 		return (start_ + duration_) > now;
// 	}

// 	~Timer() = default;
// };


// void AddHeaderCookie (Session* session,
// 					struct MHD_Response* response);

/*
	// ============= chat configuration ==========
	constexpr static size_t POSTBUFFERSIZE = 512;
	constexpr static size_t MAXNAMESIZE = 30;
	constexpr static size_t MAXANSWERSIZE = 512;
	constexpr static size_t MAXMEMBERSNUMBER = 10;
	constexpr static size_t MAXACTIVEMEMBERS = 5; 

	// ===========================================


*/

MHD_Result SendPage(
	struct MHD_Connection *connection, Session* session,
	std::string_view page, enum MHD_ResponseMemoryMode MemoryMODE = MHD_RESPMEM_PERSISTENT);

MHD_Result SendPage(
	struct MHD_Connection *connection, uint16_t http_status_code,
	std::string_view page, enum MHD_ResponseMemoryMode MemoryMODE = MHD_RESPMEM_PERSISTENT);

std::string strDBError(int16_t code, http_code_t& http_code);

MHD_Result SendStringContent(
	MHD_Connection* connection,
	const std::string& content, 
	uint16_t http_status_code);

MHD_Result SendHTMLContent(
	MHD_Connection* connection,
	const std::string& html_content, 
	uint16_t http_status_code);

// #warning 
// done for readable!
#include "Resources.cpp"

int main()
{
	// needed for registration html page

	// needed to registration static directory where browser to find 
	// images, links and etc
	assert(RegistrationPostResource::db_server_interface.open(DB_PATH) == serverDB::DB_OK && "DB conf error!");

	std::locale loc("en_US.UTF-8");
	std::locale::global(loc);

	srand(time(NULL));
	const uint16_t WEBSERVERPORT = 8888;

	Server registration_server(static_cast<MHD_FLAG>(MHD_USE_DEBUG), 
							 WEBSERVERPORT, nullptr, nullptr,
							 MHD_OPTION_CONNECTION_TIMEOUT, 15u,
							 MHD_OPTION_END);

	Resource* main_html_page = new GeneralGetResource(HTTP::GET, "/", "../html_src/sign_in.html");
	assert(registration_server.RegisterResource(main_html_page) == 0 && "Registration error!");


	Resource* reg_page = new GeneralGetResource(HTTP::GET, "/sign_up.html", "../html_src/sign_up.html");
	assert(registration_server.RegisterResource(reg_page) == 0 && "Registration error!");

	// Resource* favicon_ico = new GeneralGetResource(HTTP::GET, "/static/favicon.ico", "../html_src/static/favicon.ico");
	// assert(registration_server.RegisterResource(favicon_ico) == 0 && "Registration error!");
	

	// alternative and more comfortable way to register html
	Resource* access_member_post_data_resource = new RegistrationPostResource("/sign_in.html");
	// access_member_post_data_resource->setConfigurationPolicy(
	// 	std::bind(&RegistrationPostResource::CreatePostProcessor, access_member_post_data_resource, _1, _2),
	// 	std::bind(&RegistrationPostResource::DestroyPostProcessor, access_member_post_data_resource, _1));
	assert(registration_server.RegisterResource(access_member_post_data_resource) == 0);

	auto WorkingProcess = [&registration_server]()
	{
		fd_set 	rd_set,
				write_set,
				except_set;

		int max_ds = 0;
		MHD_UNSIGNED_LONG_LONG timeout;
		struct timeval tv;
		struct timeval* tvp;
		while(true)
		{
			FD_ZERO(&rd_set);
			FD_ZERO(&write_set);
			FD_ZERO(&except_set);
			max_ds = 0;

			if (registration_server().GetFdSets(&rd_set, &write_set, &except_set, &max_ds) == 
				MHD_NO)
			{
				std::cerr << "Working loop report: GetFdSets() error!\n";
				break;
			}

			if (registration_server().GetTimeout(&timeout) == 
				MHD_YES) /* timeout are not used or no connection uses it */
			{
				tv.tv_sec = timeout / 1000;
				tv.tv_usec = (timeout - (tv.tv_sec * 1000))  * 1000;
				tvp = &tv;
			} else 
			{
				tvp = NULL;
			}

			/* I want to add coroutine for async */
			if (select(max_ds + 1, &rd_set, &write_set, &except_set, tvp) == -1)
			{
				/* some error with system */
				perror("Working loop report: select() error ");
				break;
			}

			registration_server().run();

			// registration_server.ExpireSession();
		}
	};

	std::thread exec_daemon_loop = std::thread(WorkingProcess);

	std::getchar();

	exec_daemon_loop.detach();

	return 0;
}

// void AddHeaderCookie (Session *session,
// 					struct MHD_Response *response)
// {
// 	char cstr[256];
// 	snprintf (cstr,
// 				sizeof (cstr),
// 				"%s=%s",
// 				"Cookie",
// 				session->sid);
// 	if (MHD_NO ==
// 			MHD_add_response_header (response,
// 								 MHD_HTTP_HEADER_SET_COOKIE,
// 								 cstr))
// 	{
// 		std::cerr << 
// 			"Server::AddHeaderCookie(): Failed to set session cookie header!\n";
// 	}
// }
	

static int strcmptail(std::string_view str, std::string_view footer)
{
	ssize_t diff = str.length() - footer.length();
	if (diff < 0)
		return static_cast<int>(footer[0]);

	str.remove_prefix(diff);
	return str.compare(footer);
}

static int strcmphead(std::string_view str, std::string_view head)
{
	return str.compare(0, head.length(), head);
}


enum MHD_Result SendPage(
	struct MHD_Connection *connection, Session* session,
	std::string_view page, enum MHD_ResponseMemoryMode MemoryMODE)
{
	return SendPage(connection, session->status_code, 
		page, MemoryMODE);
}

/**
 * SendPage function excepts symbol `/' 
 * and file basename
 * 
 * */
enum MHD_Result SendPage(
	struct MHD_Connection *connection, uint16_t http_status_code,
	std::string_view page, enum MHD_ResponseMemoryMode MemoryMODE)
{
	enum MHD_Result ret;
	struct MHD_Response *response;

	if (strcmptail(page, ".html") == 0 || 
		strcmphead(page, "/static/") == 0 || page.compare("/") == 0)
	{
		std::string page_name = HTML_SRC_PATH;
		if (page.compare("/") == 0)
		{
			page_name.append("/sign_in.html");
			// send default response in server
		} else
		{
			page_name.append(page);
		}

		struct stat file_buf;
		int file_desc;
		if( (file_desc = open(page_name.c_str(), O_RDONLY)) != -1 &&
			fstat(file_desc, &file_buf) == 0)
		{
			response = MHD_create_response_from_fd(file_buf.st_size, file_desc);

			if (response == NULL)
			{
				std::cerr << "SendPage(): Failed to create response!";
				close(file_desc);
				return MHD_NO;
			}

		} else 
		{ 
			if (errno == ENOENT) // no such file or directory
			{
				// std::cerr << page_name << ": no such file or directory!\n";
				response = MHD_create_response_from_buffer(strlen(Server::NOT_FOUND),
					(void*) Server::NOT_FOUND, MHD_RESPMEM_PERSISTENT);

				if (response == NULL)
				{
					std::cerr << "SendPage(): Failed to create response!";
					return MHD_NO;
				}

				http_status_code = MHD_HTTP_NOT_FOUND;

			} else 
			{

				perror("SendPage(): Internal error");

				response = MHD_create_response_from_buffer(strlen(Server::ERROR_PAGE),
					(void*) Server::ERROR_PAGE, MHD_RESPMEM_PERSISTENT);

				if (response == NULL)
				{
					std::cerr << "SendPage(): Failed to create response!";
					return MHD_NO;
				}

				http_status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;

			}
		}
	} else // need to delete for responsibility
	{
		response =
			MHD_create_response_from_buffer ( page.length(), 
											(void *)page.data(),
											MemoryMODE); // be careful with the MemoryMODE
		if (response == NULL)
		{
			std::cerr << "SendPage(): Failed to create response!";
			return MHD_NO;
		}	
			
	}

	// AddHeaderCookie(session, response);

	ret = MHD_queue_response (connection, http_status_code, response);

	MHD_destroy_response (response);
	
	return ret;
};

// need to optimization
MHD_Result SendStringContent(
	MHD_Connection* connection,
	const std::string& content, 
	uint16_t http_status_code)
{
	std::string html_wrapper = "<html><body></body></html>";
	const size_t insert_pos = 12ul;

	html_wrapper.insert(insert_pos, content);

	return SendHTMLContent(connection, html_wrapper, http_status_code);
}

MHD_Result SendHTMLContent(
	MHD_Connection* connection,
	const std::string& html_content,
	uint16_t http_status_code)
{
	MHD_Response* response = 
		MHD_create_response_from_buffer(html_content.length(),
										(void*)html_content.data(),
										MHD_RESPMEM_MUST_COPY);
	if (!response)
	{
		// create response error
		return MHD_NO;
	}

	MHD_Result ret = MHD_queue_response(connection, http_status_code, response);

	MHD_destroy_response(response);

	return ret;
}

// ========================= DB ===================================

std::string strDBError(int16_t code, http_code_t& http_code)
{
    std::string message ;
    switch(code)
    {
        case serverDB::DB_EXEC_ERROR:
        {
        
        }
        case serverDB::DB_UNSPEC_ERROR:
        {
            message = "Internal error!\n";
            http_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }
        case serverDB::DB_NAME_BUSY:
        {
            message = "Name busy!\n";
            http_code = MHD_HTTP_CONFLICT;
            break;
        }
        case serverDB::DB_ACCS_DENIED:
        {
            // session->status_code = MHD_HTTP_FORBIDDEN;
            message = "Access denied!\n";
            http_code = MHD_HTTP_FORBIDDEN;
            break;
        }
        default:
        {
            // std::cerr << "Unexpected db error code!\n";
            message = "Internal error!\n";
            http_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
           	break;
        }
    }

    return message;
}

// ======================= end DB ==============================

// 	return MHD_YES;
// }

// void RequestCompleted (void *cls,
// 						struct MHD_Connection *connection,
// 						void **con_cls,
// 						enum MHD_RequestTerminationCode toe)
// {
// 	ConnectionInfo* con_info = (ConnectionInfo*)*con_cls;
// 	(void) cls;         /* Unused. Silent compiler warning. */
// 	(void) connection;  /* Unused. Silent compiler warning. */
// 	(void) toe;         /* Unused. Silent compiler warning. */

// 	if (con_info != NULL)
// 	{
// 		delete con_info;
// 		con_info = nullptr;
// 	}
// }

// MHD_Result FilterIP(void *cls, const struct sockaddr * addr, socklen_t addrlen)
// {
// 	return MHD_YES;
// }

// static const char* ShiftPointertoBasename(std::string_view str)
// {
// 	str.remove_prefix(str.rfind("/"));
// 	return str.data();
// }

// MHD_Result PostDataParser(SimplePostProcessor* conn, const char* data, size_t data_size)
// {
// 	return MHD_NO;
// 	// assert(false && "Imcompleted code!");
// }

// MHD_Result SingIn(
// 	struct MHD_Connection* connection,
// 	Server::Session* session,
// 	Server* back_server)
// {
// 	if (session->status_code != MHD_HTTP_OK)
// 	{
// 		auto filename_n_file = HTML::CopyFileChangeTAGvalue(Server::SIGNIN_PAGE,
// 			   {{"username", session->chat_member.name_.c_str()},
// 				{"key-word", session->chat_member.key_word_.c_str()}});
// 		if (filename_n_file.first.empty())
// 		{
// 			return SendPage(connection, session, Server::ERROR_PAGE, MHD_RESPMEM_PERSISTENT);	
// 		}

// 		HTML::AddJSAlert(filename_n_file.second, "Wrong input data!");
// 		filename_n_file.second.close();

// 		return SendPage(connection, session, ShiftPointertoBasename(filename_n_file.first.c_str()), MHD_RESPMEM_MUST_COPY);
// 	}

// 	int db_code_exec = back_server->partpants_list.AccessParticipant(con_info->session->chat_member);

// 	if (db_code_exec != serverDB::DB_OK)
// 	{
// 		ProcessDBError(db_code_exec, connection, session);

// 		return MHD_NO;
// 	} 

// 	/* success */
// 	size_t hash_from_name = std::hash<std::string>()(con_info->session->chat_member.name_);
// 	std::string hash_str_reprez = std::to_string(hash_from_name);
// 	hash_str_reprez.append(".html");
// 	SendPage(connection, session, hash_str_reprez.c_str(), MHD_RESPMEM_PERSISTENT);

// 	// SendPage(connection, session, Server::SUCCESS_PAGE, MHD_RESPMEM_PERSISTENT);

// }

// MHD_Result SingUp(
// 	struct MHD_Connection* connection,
// 	Server::Session* session,
// 	Server* back_server)
// {
// 	if (session->status_code != MHD_HTTP_OK)
// 	{
// 		auto filename_n_file = HTML::CopyFileChangeTAGvalue(Server::SIGNIN_PAGE,
// 			   {{"username", session->chat_member.name_.c_str()},
// 				{"key-word", session->chat_member.key_word_.c_str()}});
// 		if (filename_n_file.first.empty())
// 		{
// 			return SendPage(connection, session, Server::ERROR_PAGE, MHD_RESPMEM_PERSISTENT);	
// 		}

// 		HTML::AddJSAlert(filename_n_file.second, "Wrong input data!");
// 		filename_n_file.second.close();

// 		return SendPage(connection, session, ShiftPointertoBasename(filename_n_file.first.c_str()), MHD_RESPMEM_MUST_COPY);
// 	}

// 	int db_code_exec = back_server->partpants_list.AccessParticipant(con_info->session->chat_member);

// 	if (db_code_exec != serverDB::DB_OK)
// 	{
// 		ProcessDBError(db_code_exec, connection, session);

// 		return MHD_NO;
// 	} 

// 	/* success */
// 	size_t hash_from_name = std::hash<std::string>()(con_info->session->chat_member.name_);
// 	std::string hash_str_reprez = std::to_string(hash_from_name);
// 	hash_str_reprez.append(".html");
// 	SendPage(connection, session, hash_str_reprez.c_str(), MHD_RESPMEM_PERSISTENT);

// 	// SendPage(connection, session, Server::SUCCESS_PAGE, MHD_RESPMEM_PERSISTENT);

// }

// MHD_Result IteratePostData (
// 				void *coninfo_cls
// 				, enum MHD_ValueKind kind
// 				, const char *key
// 				, const char *filename
// 				, const char *content_type
// 				, const char *transfer_encoding
// 				, const char *data
// 				, uint64_t off, size_t size)
// {
// 	ConnectionInfo *con_info = (ConnectionInfo *)coninfo_cls;
// 	(void) kind;               /* Unused. Silent compiler warning. */
// 	(void) filename;           /* Unused. Silent compiler warning. */
// 	(void) content_type;       /* Unused. Silent compiler warning. */
// 	(void) transfer_encoding;  /* Unused. Silent compiler warning. */
// 	(void) off;                /* Unused. Silent compiler warning. */

	
// 	if (NULL == key)
// 		return MHD_NO;

// 	if (0 == strcmp (key, "name"))
// 	{
// 		if ((size > 0) && (size <= Server::MAXNAMESIZE))
// 		{
// 			if (CharactersFilter(data, size) != MHD_YES)
// 			{
// 				con_info->session->status_code = MHD_HTTP_BAD_REQUEST;
// 				return MHD_NO;
// 			}

// 			con_info->session->chat_member.name_.assign(data);
// 		} else 
// 		{
// 			con_info->session->status_code = MHD_HTTP_BAD_REQUEST;
// 			return MHD_NO;
// 		}
// 	} else if (0 == strcmp(key, "key word"))
// 	{
// 		if ((size > 0) && (size <= Server::MAXNAMESIZE))
// 		{
// 			if (CharactersFilter(data, size) != MHD_YES)
// 			{
// 				con_info->session->status_code = MHD_HTTP_BAD_REQUEST;
// 				return MHD_NO;
// 			}
// 			con_info->session->chat_member.key_word_.assign(data);

// 		}else 
// 		{
// 			con_info->session->status_code = MHD_HTTP_BAD_REQUEST;
// 			return MHD_NO;
// 		}
// 	} else if (0 == strcmp(key, "info")) // sign up data 
// 		{
// 		if ((size > 0))
// 		{
// 			if (CharactersFilter(data, size) != MHD_YES)
// 			{
// 				con_info->session->status_code = MHD_HTTP_BAD_REQUEST;
// 				return MHD_NO;
// 			}
// 			con_info->session->chat_member.info_.assign(data);
// 		}
// 	} else 
// 	{
// 		con_info->session->status_code = MHD_HTTP_BAD_REQUEST;
// 		return MHD_NO;
// 	}

// 	return MHD_YES;
// }


