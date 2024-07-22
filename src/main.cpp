/* Feel free to use this example code in any way
	 you see fit (Public Domain) */

#include <sys/stat.h>
#include <fcntl.h>

#include <iostream>
#include <string>
#include <thread>
#include <algorithm>
#include <functional>

#include "boost/lexical_cast.hpp"
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

MHD_Result SendStringContent(
	MHD_Connection* connection,
	const std::string& content, 
	uint16_t http_status_code);

MHD_Result SendHTMLContent(
	MHD_Connection* connection,
	const std::string& html_content, 
	uint16_t http_status_code);

// MHD_Result ReplyToOptionsMethod(MHD_Connection* connection);


// void RequestCompleted (void *cls,
// 					struct MHD_Connection *connection,
// 					void **con_cls,
// 					enum MHD_RequestTerminationCode toe);


// MHD_Result FilterIP(void *cls, const struct sockaddr * addr, socklen_t addrlen);


// MHD_Result PostDataParser(const char* data, size_t data_size);

// enum MHD_Result ReplyToConnection(
// 					void *cls, struct MHD_Connection *connection,
// 					const char *url, const char *method,
// 					const char *version, const char *upload_data,
// 					size_t *upload_data_size, void **con_cls);

// MHD_Result IteratePostData (
// 							void *coninfo_cls
// 							, enum MHD_ValueKind kind
// 							, const char *key
// 							, const char *filename
// 							, const char *content_type
// 							, const char *transfer_encoding
// 							, const char *data
// 							, uint64_t off, size_t size);


MHD_Result ProcessDBError(int16_t code, struct MHD_Connection* connection, Session* session);

class GetResource : public Server::Resource
{
public:
	GetResource(int _method, const char* _url)
		: Resource(_method, _url)
	{};

	virtual MHD_Result operator()(void* cls, struct MHD_Connection* conn,
				const char* upload_data,
				size_t* upload_data_size, void** con_cls) override
	{
		return SendPage(conn, MHD_HTTP_OK, url);
	};

	virtual ~GetResource() noexcept{};
};

class GeneralGetResource : public GetResource
{
public:
	GeneralGetResource(int _method, const char* _url, std::string_view resource_path)
		: GetResource(_method, _url)
	{
		struct stat file_buf;
		int file_desc;
		if( (file_desc = open(resource_path.data(), O_RDONLY)) != -1 &&
			fstat(file_desc, &file_buf) == 0)
		{
			general_response = MHD_create_response_from_fd(file_buf.st_size, file_desc);

			if (general_response == NULL)
			{
				std::cerr << __FUNCTION__ << ":Failed to create response!";
				close(file_desc);
				assert(false);
			}
			
		}	 else 
		{
			std::cerr << __FUNCTION__;
			perror(" error: Internal failed");
			assert(false);
		}
	};

	MHD_Result operator()(void* cls, struct MHD_Connection* conn,
			const char* upload_data,
			size_t* upload_data_size, void** con_cls) override
	{
		return MHD_queue_response(conn, MHD_HTTP_OK, general_response);
	};

	virtual ~GeneralGetResource() noexcept
	{
		if (general_response)
			MHD_destroy_response(general_response);
	}

private:
	MHD_Response* general_response;
};

class PostDataUtils
{
public:

	static bool FilterCharacters(const char* c_str, size_t size)
	{
		while (size != 0)
		{
			--size;
			if (!isalpha(c_str[size]) && !isdigit(c_str[size]) && 
				 c_str[size] != ' ' && c_str[size] != '_')
				return false;
		}

		return true;
	};

	// TODO: friend of my parent is my friend?
	// friend RegistrationPostResource;

	static bool IsParticipantCompleted(const Participant& member, std::string_view url)
	{
		return (url.compare("/sign_in.html") == 0 || url.compare("/sign_up.html") == 0 || url.compare("/") == 0) 
			&& !member.name.empty() && !member.password.empty(); /* && member.info.empty() */

	};
private:
	static MHD_Result ProcessDBError(int16_t code, struct MHD_Connection* connection, Session* session)
	{
		switch(code)
		{
			case serverDB::DB_EXEC_ERROR:
			{
				// internal error
			}
			case serverDB::DB_UNSPEC_ERROR:
			{
				session->status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
				break;
			}
			case serverDB::DB_NAME_BUSY:
			{
				session->status_code = MHD_HTTP_CONFLICT;
				break;
			}
			case serverDB::DB_ACCS_DENIED:
			{
				session->status_code = MHD_HTTP_FORBIDDEN;
				break;
			}
			default:
			{
				std::cerr << "Unexpected db error code!\n";
				return MHD_YES;
			}
		}

		return 
			SendPage(connection, session, Server::ERROR_PAGE, MHD_RESPMEM_MUST_COPY);
	}
};

// general post resource
// class PostResource : public Server::Resource
// {
// public:
// 	// typedef MHD_Result (PostDataHandler)(MHD_Connection*, Session*);
// 	typedef MHD_Result (PostDataHandler )(MHD_Connection*                     );
// 	typedef MHD_Result (PostDataIterator)(MHD_Connection*, const char*, size_t);

// 	PostResource(const char* _url, 
// 				PostDataIterator _process_post_data,
// 				PostDataHandler  _handle_post_data)
// 		: Resource(HTTP::POST, _url)
// 		, process_post_data(_process_post_data)
// 		, handle_post_data(_handle_post_data)
// 	{};

// 	virtual MHD_Result operator()(void* cls, struct MHD_Connection* connection,
// 				const char* upload_data,
// 				size_t* upload_data_size, void** con_cls) override
// 	{	
// 		if (*upload_data_size > 0)
// 		{
// 			process_post_data(connection, 
// 				upload_data, *upload_data_size);

// 			return MHD_YES;
// 		}

// 		// return handle_post_data(connection, session);
// 		return handle_post_data(connection);
// 	};

// private: // members
// 	std::function<PostDataIterator> process_post_data;
// 	std::function<PostDataHandler > handle_post_data;
// };

// for sign in and sign up
class RegistrationPostResource : public Server::Resource // PostResource
{
public:
	RegistrationPostResource(const char* _url)
		: Resource(HTTP::POST, _url)
	{};

	MHD_Result HandlePostData(MHD_Connection* connection, void** con_cls)
	{
		if (!PostDataUtils::IsParticipantCompleted(member, url))
		{
			Server::SendBadRequestResponse(connection);
			// not completed data
			return MHD_NO;
		}

		// login 
		if (strcmp(url, "/") == 0 || strcmp(url, "/sign_in.html") == 0)
		{
			// request to db
		} else // dont need to check url
		{
			// request to db
		}

		// start from it 
		std::cerr << "All are ok!\n";
		return MHD_YES;

	};

	virtual MHD_Result operator()(void* cls, struct MHD_Connection* connection,
				const char* upload_data,
				size_t* upload_data_size, void** con_cls) override
	{	
		if (*upload_data_size > 0)
		{
			MHD_post_process(reinterpret_cast<MHD_PostProcessor*>(*con_cls), 
				upload_data, *upload_data_size);

			*upload_data_size = 0; // ????

			return MHD_YES;
		}
#warning "Bad responsibility of upload_data!"

		// return handle_post_data(connection, session);
		return HandlePostData(connection, con_cls);
	};

	static MHD_Result PostIterator(void *cls, enum MHD_ValueKind kind, 
					const char *key, const char *filename, 
					const char *content_type, const char *transfer_encoding, 
					const char *data, uint64_t off, size_t size)
	{
		std::ignore = kind;
		std::ignore = filename;
		std::ignore = content_type;
		std::ignore = transfer_encoding;
		std::ignore = off;

		if (size > 0)
		{ // for now it is only @sign in@ option
			if (!PostDataUtils::FilterCharacters(data, size))
			{
				return MHD_NO;
			}

			RegistrationPostResource* res = 
				reinterpret_cast<RegistrationPostResource*>(cls);
			
			Participant& member = res->member;
			
			SWITCH(key)
			{
				CASE("name"):
				{
					member.name.append(data);
					break;
				}
				CASE("password"):
				{
					member.password.append(data);
					break;
				}
				CASE("info"):
				{
					member.info.append(data);
					break;
				}
				DEFAULT:
				{
					return MHD_NO;
				}
			}
		}

		return MHD_YES;
	};

	// configuration for first connection
	// imitation of ctor
	MHD_Result Configure(MHD_Connection* conn, void** con_cls) override
	{
		// clear resources
		member.clear();
		uniq_pp.reset(nullptr);

		// get resources		
		auto temp = CreatePostProcessor(conn);
		if (!temp)
		{
			Server::SendBadRequestResponse(conn);
			return MHD_NO;
		}

		uniq_pp.reset(temp);

		*con_cls = uniq_pp.get();

		return MHD_YES;
	}

	// termination connection
	// imitation of dtor
	void Release(void** con_cls) override
	{
		std::ignore = con_cls;

		uniq_pp.reset(nullptr);
	}

	class PostProcessorDestroyer
	{
	public:
		auto operator()(MHD_PostProcessor* pp) const noexcept
			-> decltype(MHD_destroy_post_processor(pp)) 
		{
			if (pp)
			{
				return MHD_destroy_post_processor(pp);
			}

			return MHD_YES;
		};
	};
private: // methods
	MHD_PostProcessor* CreatePostProcessor(MHD_Connection* conn) // const
	{	
		const char* content_type = MHD_lookup_connection_value(conn, MHD_HEADER_KIND,
			"Content-Type");

		// what associative of || operator --> or <--
		if (!content_type || !AvailableContentType(content_type))
		{
			SendStringContent(conn, 
				"Instance of content-type header not allowed!", MHD_HTTP_BAD_REQUEST);
			return nullptr;
		}

		MHD_PostProcessor* temp_pp = MHD_create_post_processor(
			conn, kPostBufferSize, 
			&RegistrationPostResource::PostIterator, 
			reinterpret_cast<void*>(this));
		if (!temp_pp)
		{
			Server::SendInternalErrResponse(conn);
			return nullptr;
		}

		return temp_pp;
	}


	inline bool AvailableContentType(std::string_view content_type) const 
	{
		// this values are passed by MHD
		return (content_type.compare(MHD_HTTP_POST_ENCODING_FORM_URLENCODED) == 0) ||
			(content_type.compare(MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA) == 0);
	}

private: // members
	static const size_t kPostBufferSize = 512;
	Participant member;
	std::unique_ptr<MHD_PostProcessor, PostProcessorDestroyer> uniq_pp;
	// Session* session;
	// static SessionsList session_list;
};

int main()
{
	// needed for registration html page

	// needed to registration static directory where browser to find 
	// images, links and etc

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


