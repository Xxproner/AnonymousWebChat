/* Feel free to use this example code in any way
	 you see fit (Public Domain) */

#include <sys/stat.h>
#include <fcntl.h>

#include <iostream>
#include <string>
// #include <thread>
#include <algorithm>
#include <functional>
#include <cassert>
#include <filesystem>
#include <map>
#include <system_error>
#include <forward_list>

namespace fs = std::filesystem;
using namespace std::placeholders;

#include "boost/lexical_cast.hpp"
#include "boost/json/src.hpp"

using boost::lexical_cast;
using boost::bad_lexical_cast;

#include "Server.hpp"
#include "htmlUtils.hpp"
#include "SessionList.hpp"
#include "ServerDB.hpp"

using Resource = Server::Resource;


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

typedef uint16_t http_code_t;


MHD_Result SendFile(
	struct MHD_Connection *connection, Session* session,
	std::string_view page, enum MHD_ResponseMemoryMode MemoryMODE = MHD_RESPMEM_PERSISTENT);
/**
 * send file
 * */
MHD_Result SendFile(
	struct MHD_Connection *connection, uint16_t http_status_code,
	std::string_view page, enum MHD_ResponseMemoryMode MemoryMODE = MHD_RESPMEM_PERSISTENT);

std::string DBErrorStrInfo(int16_t code, http_code_t& http_code);

MHD_Result SendStringContent(
	MHD_Connection* connection,
	const std::string& content, 
	uint16_t http_status_code);

MHD_Result SendStringAsHTML(
	MHD_Connection* connection,
	const std::string& content, 
	uint16_t http_status_code);

MHD_Result SendHTMLContent(
	MHD_Connection* connection,
	const std::string& html_content, 
	uint16_t http_status_code);

namespace hidden 
{

	struct c_strComparer
	{
		bool operator()(const char* lhs, const char* rhs) const noexcept 
		{
			return std::char_traits<char>::compare(lhs, rhs, 
				std::char_traits<char>::length(lhs)) < 0;
		};
	};

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

	class ResponseDestroyer
	{
	public:
		void operator()(MHD_Response* response) const noexcept
		{
			if (response)
			{
				MHD_destroy_response(response);
			}
		}
	};

}; // namespace hidder


class CommonGetResource : public Server::Resource
{
public:
	CommonGetResource(const char* _url, const std::string& _filename)
		: Resource(_url),
		filename(_filename)
	{
		assert (fs::exists(_filename) == true);
	};

	virtual MHD_Result DoGET(struct MHD_Connection* conn,
		const char* url) override
	{
		return SendFile(conn, MHD_HTTP_OK, url);
	};

	virtual ~CommonGetResource() noexcept{};

private:
	const std::string filename;
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

	static bool IsParticipantCompleted(const Participant& member, std::string_view url)
	{
		return (url.compare("/sign_in.html") == 0 || url.compare("/sign_up.html") == 0 || url.compare("/") == 0) 
			&& !member.name.empty() && !member.password.empty(); /* && member.info.empty() */

	};

	static std::string_view FindCookieValuebyName(std::string_view cookies, std::string_view name)
	{
		size_t pos = cookies.find(name);

		if (pos == std::string_view::npos)
		{
			return {cookies.data(), 0};
		}

		size_t start_value_pos = 0;
		pos += name.length();
		while (pos != cookies.length())
		{
			if (cookies[pos] == ' ' || cookies[pos] == '=')
			{
				// skip
			} else if (cookies[pos] == ';')
			{
				break;
			} else // value
			{
				if (!start_value_pos)
				{
					start_value_pos = pos;
				}
			}

			++pos;
		}

		return {cookies.data() + start_value_pos, pos - start_value_pos};
	};
private:
};


class MainResource : public Server::Resource 
{
public:

	class request_category : public generic_category 
	{
		// nothing
	};

	MainResource(const char* _url, const std::string& _filename)
		: Resource(_url)
		, filename(_filename)
	{
		assert (fs::exists(_filename) == true);

		MHD_Response* temp_redirect = MHD_create_response_from_buffer(0,
			(void*)"", MHD_RESPMEM_MUST_COPY); 

		assert(temp_redirect);
		assert(MHD_add_response_header(temp_redirect, MHD_HTTP_HEADER_LOCATION, "/login") == MHD_YES);

		redirect_to_login_response.reset(temp_redirect);
	};

	MHD_Result DoGET(struct MHD_Connection* connection,
		const char* url) override
	{
		bool is_ok = true;
		if ((const char* cookies = MHD_lookup_connection_value(
			connection, MHD_COOKIE_KIND, "Cookie")) != NULL)
		{
			// super slow
			MainResource::sessions_list.ExpireSession();

			// string view is pointer and size_t
			std::string_view session_id = PostDataUtils::FindCookieValuebyName(cookies, "__Secure-sessionid");

			if (!session_id.empty())
			{
				auto found_session = MainResource::sessions_list.FindSession(session_id);
				if (!found_session || !found_session->verificate) { is_ok = false; }

			} else { is_ok = false; }

		} else { is_ok = false; }
		
		if (!is_ok)
		{
			return 
				MHD_queue_response(connection, 303, redirect_to_login_response.get());
		}

		return SendFile(connection, MHD_HTTP_OK, filename);
	};

public:

	~MainResource() noexcept{};

private:
	const std::string filename;
	std::unique_ptr<MHD_Response, hidden::ResponseDestroyer> redirect_to_login_response;

	static serverDB server_db;
	static SessionsList sessions_list;
};

/////////////////////////////========================///////////////

class RegistrationResource : public Server::Resource 
{
public:

	class request_category : public generic_category 
	{
		// nothing
	};

	RegistrationResource(const char* _url, const std::string& _filename)
		: Resource(_url)
		, filename(_filename)
	{
		assert (fs::exists(_filename) == true);

		MHD_Response* temp_redirect = MHD_create_response_from_buffer(0,
			(void*)"", MHD_RESPMEM_MUST_COPY); 

		assert(temp_redirect);
		assert(MHD_add_response_header(temp_redirect, MHD_HTTP_HEADER_LOCATION, "/") == MHD_YES);

		redirect_to_main_response.reset(temp_redirect);
	};

	MHD_Result DoGET(struct MHD_Connection* connection,
		const char* url) override
	{
		return SendFile(connection, MHD_HTTP_OK, filename);
	};

private:
	const std::string filename;

public:
	MHD_Result Required(MHD_Connection* conn, const char* uri, const char* method) override
	{
		if (strcmp(method, MHD_HTTP_METHOD_POST) == 0)
		{
			// clear resources
			member.clear();
			uniq_pp.reset(nullptr);

			// get resources		
			std::error_code pp_create_err;
			CreatePostProcessor(conn, pp_create_err);
			
			if (pp_create_err.value() != 0)
			{
				Server::SendBadRequestResponse(conn);
				return MHD_NO;
			}
		}

		return MHD_YES;
	};


	MHD_Result DoPOST(struct MHD_Connection* connection,
		const char* url, const char* upload_data, size_t upload_data_size) override
	{
		if (upload_data_size > 0)
		{
			MHD_post_process(uniq_pp.get(), 
				upload_data, upload_data_size);

			return MHD_YES;
		}

		return HandlePostData(connection);
	};

	enum {
		DISALLOW_PP_CONTENT_TYPE = 1,
		MHD_INTERNAL_ERROR
	};

	// and picture
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

			RegistrationResource* res = 
				reinterpret_cast<RegistrationResource*>(cls);
			
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

	MHD_Result HandlePostData(MHD_Connection* connection)
	{
		if (!PostDataUtils::IsParticipantCompleted(member, url))
		{
			// not completed data
			Server::SendBadRequestResponse(connection);
			return MHD_NO;
		}

		int db_exec_code = 0;
		if (strcmp(url, "/login") == 0)
		{
			db_exec_code = MainResource::server_db.AccessParticipant(member);
		} else if (strcmp(url, "/registration") == 0)
		{
			db_exec_code = MainResource::server_db.AddParticipant(member);
		}

		// if we don't call queue_response 
		// then microhttpd craches
		if (db_exec_code != serverDB::DB_OK)
		{
			http_code_t http_response_code = 400;
			std::string db_bad_message = DBErrorStrInfo(db_exec_code, http_response_code);
			return SendContentAsHTML(connection, db_bad_message, http_response_code);
		}

		Session* new_session = new Session();

		new_session.CreateSessionCookie(std::chrono::hours{1});

		MainResource::sessions_list.AddSession(new_session);

		MHD_Response* all_ok_response 
			= MHD_create_response_from_buffer(0, (void*)"", MHD_RESPMEM_MUST_COPY);

		// we can use put method
		char cookie_str[129];

		std::string expired_http_date = new_session.ExpiredTimeToHTTPDate();

		snprintf(cookie_str, 129, ", __Secure-sessionid=%s; Expires= %s; Path=/", new_session->cookie, expired_http_date.c_str());
		MHD_add_response_header(all_ok_response, MHD_HTTP_HEADER_SET_COOKIE, cookie_str);
		MHD_add_response_header(all_ok_response, MHD_HTTP_HEADER_LOCATION, "/");

		MHD_Result lazy_ret = MHD_queue_response(connection, 303, response);
		if (lazy_ret == MHD_NO)
		{
			std::cerr << "MHD_queue_response(): MHD internal error!" << 
				__FILE__ << " " << __LINE__;
		}

		MHD_destroy_response(response);

		return lazy_ret;

	};

private: // methods
	inline bool AvailableContentType(std::string_view content_type) const 
	{
		// this values are passed by MHD
		return (content_type.compare(MHD_HTTP_POST_ENCODING_FORM_URLENCODED) == 0) ||
			(content_type.compare(MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA) == 0);
	}

	void CreatePostProcessor(MHD_Connection* conn, std::error_code& err_code) // const
	{	
		const char* content_type = MHD_lookup_connection_value(conn, MHD_HEADER_KIND,
			"Content-Type");

		// what associative of || operator --> or <--
		if (!content_type && AvailableContentType(content_type))
		{
			err_code.assign(DISALLOW_PP_CONTENT_TYPE, request_category);
			return;
		}

		MHD_PostProcessor* temp_pp = MHD_create_post_processor(
			conn, 512, 
			&RegistrationResource::PostIterator, 
			reinterpret_cast<void*>(this));
		
		if (!temp_pp)
		{
			err_code.assign(MHD_INTERNAL_ERROR, request_category{});
			return ;
		}

		uniq_pp.reset(temp_pp);

		return; 
	}

	~RegistrationResource() noexcept{};

private: // members
	Participant member;
	std::unique_ptr<MHD_PostProcessor, hidden::PostProcessorDestroyer> uniq_pp;

	std::unique_ptr<MHD_Response, hidden::ResponseDestroyer> redirect_to_main_response;
};

int main()
{
	std::locale loc("en_US.UTF-8");
	std::locale::global(loc);
	
	assert(MainResource::server_db.open(DB_PATH) == serverDB::DB_OK && "DB open error!");

	const uint16_t WEBSERVERPORT = 8888;
	Server registration_server(MHD_NO_FLAG, 
							 WEBSERVERPORT, nullptr, nullptr,
							 MHD_OPTION_CONNECTION_TIMEOUT, 15u); // start daemon

	// Resource* main_page = new MainResource("/", "../html_src/index.html")
	// assert(registration_server.RegisterResource(main_page) == 0 && "Registration error!");

	Resource* login_html_page = new RegistrationResource("/login", "../html_src/sign_in.html");
	assert(registration_server.RegisterResource(login_html_page) == 0 && "Registration error!");

	Resource* reg_page = new RegistrationResource("/registration", "../html_src/sign_up.html");
	assert(registration_server.RegisterResource(reg_page) == 0 && "Registration error!");

	// register static folder
	// const char* static_folder_path = "../html_src/static/";
	// assert(RegisterStaticFolder(static_folder_path) == 0);
	// Resource* favicon_ico = new CommonGetResource("/static/favicon.ico", "../html_src/static/favicon.ico");
	// assert(registration_server.RegisterResource(favicon_ico) == 0 && "Registration error!");
	
	// register one resource to pack of pathes

	bool is_blocked;
	registration_server.StartServer(is_blocked = false);

	// while()
	// {
		char ch = getchar();
		
	// }



	registration_server.StopServer(false);
	
	// clear resources
	MainResource::server_db.close();

	return 0;
}	

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


enum MHD_Result SendFile(
	struct MHD_Connection *connection, Session* session,
	std::string_view page, enum MHD_ResponseMemoryMode MemoryMODE)
{
	return SendFile(connection, 200, 
		page, MemoryMODE);
}

enum MHD_Result SendFile(
	struct MHD_Connection *connection, uint16_t http_status_code,
	std::string_view page, enum MHD_ResponseMemoryMode MemoryMODE)
{
	static std::map<const char*, const char*, hidden::c_strComparer> mContentType = {
		{".jpg" , "image/jpeg"}, {".ico", "image/x-icon"	},
		{".html", "text/html" }, {".js" , "text/javascript"	}
	};

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

		const char* content_type;

		// get content type
		std::string path_extension = fs::path(page_name).extension().string();
		auto mime_type = mContentType.find(path_extension.c_str());
		if (mime_type == mContentType.cend())
		{
			std::cerr << "Unknown path extension (" << path_extension << ")!\n";
			content_type = "text/plain";
		} else 
		{
			content_type = mime_type->second;
		}

		struct stat file_buf;
		int file_desc;
		if( (file_desc = open(page_name.c_str(), O_RDONLY)) != -1 &&
			fstat(file_desc, &file_buf) == 0)
		{
			response = MHD_create_response_from_fd(file_buf.st_size, file_desc);

			if (response == NULL)
			{
				std::cerr << "SendFile(): Failed to create response!";
				close(file_desc);
				return MHD_NO;
			}

			MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, content_type);
		} else 
		{ 
			if (errno == ENOENT) // no such file or directory
			{
				// std::cerr << page_name << ": no such file or directory!\n";
				response = MHD_create_response_from_buffer(strlen(Server::NOT_FOUND),
					(void*) Server::NOT_FOUND, MHD_RESPMEM_PERSISTENT);

				if (response == NULL)
				{
					std::cerr << "SendFile(): Failed to create response!";
					return MHD_NO;
				}

				http_status_code = MHD_HTTP_NOT_FOUND;

			} else 
			{
				perror("SendFile(): Internal error");

				return Server::SendInternalErrResponse(connection);
			}
		}

	}
	// } else // need to delete for responsibility
	// {
	// 	response =
	// 		MHD_create_response_from_buffer (page.length(), 
	// 										(void*)page.data(),
	// 										 MemoryMODE); // be careful with the MemoryMODE
	// 	if (response == NULL)
	// 	{
	// 		std::cerr << "SendFile(): Failed to create response!";
	// 		return MHD_NO;
	// 	}	
			
	// }

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
	MHD_Response* response = 
		MHD_create_response_from_buffer(content.length(),
										(void*)content.data(),
										MHD_RESPMEM_MUST_COPY);
	if (!response)
	{
		// create response error
		return MHD_NO;
	}

	MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain");

	MHD_Result ret = MHD_queue_response(connection, http_status_code, response);

	MHD_destroy_response(response);

	return ret;
}

MHD_Result SendStringAsHTML(
	MHD_Connection* connection,
	const std::string& content,
	uint16_t http_status_code)
{
	std::string html_content = "<html><body>?</html></body>";
	size_t insert_pos = html_content.find('?');
	html_content.replace(insert_pos, 1, content);

	return SendHTMLContent(connection, html_content, http_status_code);
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

	MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html");

	MHD_Result ret = MHD_queue_response(connection, http_status_code, response);

	MHD_destroy_response(response);

	return ret;
}

// ========================= DB ===================================

std::string DBErrorStrInfo(int16_t code, http_code_t& http_code)
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
// 			return SendFile(connection, session, Server::ERROR_PAGE, MHD_RESPMEM_PERSISTENT);	
// 		}

// 		HTML::AddJSAlert(filename_n_file.second, "Wrong input data!");
// 		filename_n_file.second.close();

// 		return SendFile(connection, session, ShiftPointertoBasename(filename_n_file.first.c_str()), MHD_RESPMEM_MUST_COPY);
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
// 	SendFile(connection, session, hash_str_reprez.c_str(), MHD_RESPMEM_PERSISTENT);

// 	// SendFile(connection, session, Server::SUCCESS_PAGE, MHD_RESPMEM_PERSISTENT);

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
// 			return SendFile(connection, session, Server::ERROR_PAGE, MHD_RESPMEM_PERSISTENT);	
// 		}

// 		HTML::AddJSAlert(filename_n_file.second, "Wrong input data!");
// 		filename_n_file.second.close();

// 		return SendFile(connection, session, ShiftPointertoBasename(filename_n_file.first.c_str()), MHD_RESPMEM_MUST_COPY);
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
// 	SendFile(connection, session, hash_str_reprez.c_str(), MHD_RESPMEM_PERSISTENT);

// 	// SendFile(connection, session, Server::SUCCESS_PAGE, MHD_RESPMEM_PERSISTENT);

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


