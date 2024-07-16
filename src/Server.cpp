#include "Server.hpp"

// #include <time.h>

#include <iostream>
#include <fstream>
#include <algorithm>
#include <chrono>
#include <cassert>
#include <regex>

// #include "htmlParser.hpp"

#warning "ServerDB is public member!"

// ssize_t *MHD_ContentReaderCallback (void *cls, uint64_t pos, char *buf, size_t max)
ssize_t Server::xxFileReaderCallback(void* cls, uint64_t pos, char* buf, size_t max)
{
	std::ifstream* file = reinterpret_cast<std::ifstream*>(cls);
	
	if (file->eof())
	{
		return MHD_CONTENT_READER_END_OF_STREAM;;
	}

	char ch = 0; ssize_t curr = 0;
	while((ch = file->get()) && 
		curr < max) 
	{	
		buf[curr] = ch;
		++curr;
	}

	return curr;
}

// void *MHD_ContentReaderFreeCallback (void *cls)
void Server::xxContentReaderFreeCallback (void *cls)
{
	std::ifstream* file = 
		reinterpret_cast<std::ifstream*>(cls);

	file->close();
	delete file;
}

// struct MHD_Response * MHD_create_response_from_callback (uint64_t size, size_t block_size, MHD_ContentReaderCallback crc, void *crc_cls, MHD_ContentReaderFreeCallback crfc)
MHD_Result Server::SendFile(
	struct MHD_Connection *connection, 
	std::string_view page,
	uint16_t http_status_code)
{
	enum MHD_Result ret;
	struct MHD_Response *response;

	std::string page_name = HTML_SRC_PATH;
	if (page.compare("/") == 0)
	{
		page_name.append("/sign_in.html");
	} else
	{
		page_name.append(page);
	}

	std::ifstream* file = new std::ifstream(page_name, std::ios_base::in | std::ios_base::binary);
	if (!file->is_open())
	{
#ifdef DEBUG
		fprintf(stderr, "Bound file[%s] with resource open error!\n", page_name.c_str());
#endif // DEBUG
		return SendInternalErrResponse(connection);
	}

	response = MHD_create_response_from_callback(-1, 1024 * 2, &Server::xxFileReaderCallback,
		reinterpret_cast<void*>(file), &Server::xxContentReaderFreeCallback);

	if (!response)
	{
		// std::cerr << "Invalid created response!\n";
		return MHD_NO;
	}
	// if( (file_desc = open(page_name.c_str(), O_RDONLY)) != -1 &&
	// 	fstat(file_desc, &file_buf) == 0)
	// {
	// 	response = MHD_create_response_from_fd(file_buf.st_size, file_desc);

	// 	if (response == NULL)
	// 	{
	// 		std::cerr << "SendPage(): Failed to create response!";
	// 		close(file_desc);
	// 		return MHD_NO;
	// 	}

	// } else 
	// { 
	// 	if (errno == ENOENT) // no such file or directory
	// 	{
	// 		// std::cerr << page_name << ": no such file or directory!\n";
	// 		return SendNotFoundResponse(connection);
	// 	} else 
	// 	{
	// 		return SendInternalErrResponse(connection);
	// 	}
	// }

	ret = MHD_queue_response (connection, http_status_code, response);

	MHD_destroy_response (response);
	
	return ret;
};


int Server::CombMethod(std::string_view finding_method) const
{
	const static std::map<std::string_view, int> methods = {
		{"GET", 0}, {"HEAD", 1}, {"POST", 2}, {"PUT", 3},  {"DELETE", 4}, 
		{"CONNECT", 5}, {"TRACE", 6}, {"OPTIONS", 7}, {"PATCH", 8}
	};

	const auto methd_n_code = methods.find(finding_method);

	return methd_n_code != methods.cend() ? methd_n_code->second : -1;
}

MHD_Result Server::SendInternalErrResponse(MHD_Connection* connection)
{
	MHD_Response* not_found_response = 
		MHD_create_response_from_buffer(strlen(NOT_FOUND), 
			(void*)NOT_FOUND, MHD_RESPMEM_PERSISTENT);
	if (!not_found_response)
	{
		return MHD_NO;
	}

	MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, not_found_response);

	MHD_destroy_response(not_found_response);

	return ret;
}


MHD_Result Server::SendNotFoundResponse(MHD_Connection* connection)
{
	MHD_Response* not_found_response = 
		MHD_create_response_from_buffer(strlen(INTERNAL_ERROR), 
			(void*)INTERNAL_ERROR, MHD_RESPMEM_PERSISTENT);
	if (!not_found_response)
	{
		return MHD_NO;
	}

	MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, not_found_response);

	MHD_destroy_response(not_found_response);

	return ret;
}

/*
authentificate needs to every connection?
*/
//TODO: add hash password!
MHD_Result Server::BasicAuth(MHD_Connection* conn, const std::string& username, 
	const std::string& passw, const std::string& realm)
{
	char* conn_passw = nullptr;
	char* conn_name =  MHD_basic_auth_get_username_password(conn, &conn_passw);
	
	bool fail = ( (NULL == conn_name) || (NULL == conn_passw) ||
				username.compare(conn_name) || passw.compare(conn_passw));

	if (conn_name)
	{
		MHD_free(conn_name);
	}

	if (conn_passw)
	{
		MHD_free(conn_passw);
	}

	if (fail)
	{
		MHD_Response* basic_auth_fail_res = 
			MHD_create_response_from_buffer(strlen(Server::DENIED), (void*)Server::DENIED, MHD_RESPMEM_PERSISTENT);
		MHD_queue_basic_auth_fail_response(conn, realm.c_str(), basic_auth_fail_res);

		MHD_destroy_response(basic_auth_fail_res);
		return MHD_NO;
	}

	return MHD_YES;
}


/*MHD_Result Server::DigestAuth(struct MHD_Connection* connection,
	const std::string& username, const std::string& passw, 
	const std::string& realm, const std::string& opaque, 
	enum MHD_DigestAuthAlgorithm alg, unsigned int nonce_timeout)
{
	enum MHD_Result ret;
	struct MHD_Response* response = nullptr;

	const char* c_realm = realm.c_str(),
				c_username = username.c_str(),
				c_passw = passw.c_str(),
				c_opaque = opaque.c_str();

	char* conn_username = MHD_digest_auth_get_username (connection);
	if (username == NULL)
	{
		response = MHD_create_response_from_buffer(strlen (DENIED),
													 (void*)DENIED,
													 MHD_RESPMEM_PERSISTENT);
		ret = MHD_queue_auth_fail_response2 (connection,
											 c_realm,
											 c_opaque,
											 response,
											 (int)MHD_NO,
											 alg);
		MHD_destroy_response(response);
		return MHD_NO;
	}

	ret = (MHD_Result) MHD_digest_auth_check2(connection,
										c_realm,
										conn_username,
										c_passw,
										nonce_timeout,
										alg);
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
										c_realm,
										c_opaque,
										response,
										(ret == MHD_INVALID_NONCE) ? MHD_YES : MHD_NO,
										alg);
		MHD_destroy_response(response);
		return MHD_NO;
	}

	return MHD_YES;
}*/

MHD_Result Server::JWTAuth(struct MHD_Connection* conn)
{
	assert(false && "Imcompleted!");
}

/**
 * static function 
 * */
MHD_Result Server::ReplyToConnection(
					void *cls, struct MHD_Connection *connection,
					const char *url, const char *method,
					const char *version, const char *upload_data,
					size_t *upload_data_size, void **con_cls)
{
	Server* backvalue_server = 
		reinterpret_cast<Server*>(cls);

	int method_number = backvalue_server->CombMethod(method);
	// dont need to check method

	Resource* found_resource = backvalue_server->FindResource(
		method_number, url);

	if (found_resource == nullptr)
	{
#ifdef DEBUG
		std::cerr << method << " " << url << ": resource not found!\n";
#endif /* DEBUG */
		return backvalue_server->SendNotFoundResponse(connection);
	}

	// if (resource->configured)
	// {
		
	// }


	return found_resource->operator()(con_info, connection,
		upload_data, 
		upload_data_size, con_cls);

	// available methods
	// if (strcmp(method, MHD_HTTP_METHOD_POST) != 0 && 
	// 	strcmp(method, MHD_HTTP_METHOD_GET) != 0)
	// {
	// 	if (strcmp(method, MHD_HTTP_METHOD_OPTIONS) == 0)
	// 	{
	// 		return back_server->ReplyToOptionsMethod(connection);
	// 	} else 
	// 	{
	// 		session->STATUS_CODE = HTTP::HttpStatusCode::MethodNotAllowed;
	// 		return SendPage(connection, session, Server::ERROR_PAGE, MHD_RESPMEM_PERSISTENT);
	// 	}
	// }

	// authorization
	// if (!session->verificate)
	// {
	// 	if (Server::BasicVerificate(connection) == MHD_YES)
	// 	// if (Server::DGVerificate(connection) == MHD_YES)
	// 	{
	// 		session->verificate = true;
	// 	}
	// }

	// char page[64]; 
	// memcpy(page, Server::SIGNIN_PAGE, strlen(Server::SIGNIN_PAGE) + 1);

	// if (0 == strcmp (method, MHD_HTTP_METHOD_POST))
	// {
	// 	if (*upload_data_size != 0)
	// 	{
	// 		con_info->PostProcess(upload_data, *upload_data_size);		
			
	// 		*upload_data_size = 0;	
	// 		return MHD_YES;
	// 	}

	// 	if (strcmp(url, "/sign_up.html") == 0)
	// 	{
	// 		SignUp();
	// 	} else if (strcmp(url, "/sign_in.html") == 0)
	// 	{
	// 		SignIn();
	// 	}
	// } else if (0 == strcmp (method, MHD_HTTP_METHOD_GET))
	// {
	// 	return SendPage(connection, session, url); // <--- url
	// }

	// std::cerr << "Unexpected terminating connection!\n";
	
}

char* strdupxx(std::string_view str)
{
	size_t str_len = str.length();
	char* new_str = new char[str_len];
	std::char_traits<char>::copy(new_str, str.data(), str_len + 1); // terminating zero
	return new_str;
}

Server::Resource::Resource(int _method, const char* _url)
	: method(_method)
	, url(strdupxx(_url))
	, configured(false)
{
}


Server::Resource::~Resource()
{
	if (url)
	{
		delete[] url; 
	}
}


int Server::GeneralServerGetResource::RegistrationTimeCheck() const noexcept
{
	return 0;
};

MHD_Result Server::GeneralServerGetResource::operator()(void* cls, 
	struct MHD_Connection* conn,
	const char* upload_data,
	size_t* upload_data_size)
{
	return SendFile(conn, filename.c_str());
}

int Server::RegisterResource(Resource* res)
{
	const auto hint = resources.lower_bound(*res);
	if (hint != resources.cend())
	{
		auto fin_range = std::next(hint);
		while ((fin_range != resources.cend()) && 
			((*fin_range).get()->operator==(*res))) // equivalent key
		{
			if ((*fin_range)->method == res->method) // equivalent url and method is not allowed
			{
				return -1;
			}

			++fin_range;
		}
	}

	resources.emplace_hint(hint, res);
	return 0;
}

/*int Server::RegisterHTMLPage(const char* url, const char* file)
{
	// internal src is added external skip
	// difference between /image.png and image.png
	// is /image.png is absolute file path but image.png is relative
	// we should classificate resources

	HTML::Parser src_parser;

	Resource* res = nullptr;

	std::string_view name_base_file = basename(url);

	res = new GeneralServerGetResource(url, name_base_file);

	if (static_cast<GeneralServerGetResource*>(res)->RegistrationTimeCheck() != 0)
	{
#ifdef DEBUG
		std::cerr << "Resource error!\n";
#endif	
		return -1;	
	}


	if (RegisterResource(res) != 0)
	{
#ifdef DEBUG
		std::cout << "Base resource registration failed!\n";
#endif
		return -1;
	}

	if (src_parser.init(url) == -1)
	{
#ifdef DEBUG
		std::cout << "Unspecific internal error!\n";
#endif
		return -1;
	}

	auto JustFilename = [](const std::string& possbl_filename)
	{
		static std::regex filename_reg("\\w+(\\.\\w+)?");
		return std::regex_match(possbl_filename, filename_reg);
	};

	// std::wstring path_src_attr;
	std::string path_src_attr;
	
	// const wchar_t* base_dir_path = basename(url);		
	// std::wstring file_name(base_dir_path); 
	std::string_view dir_path = Helper::dirname(url); 

	std::string file_name(dir_path);
	std::string::const_iterator basedir_end_iter = file_name.cend();

	while (!(path_src_attr = src_parser.parse()).empty())
	{
		if (path_src_attr[0] == '/')
		{
			// resource url ----> url/path_src_attr
			res = new GeneralServerGetResource(&path_src_attr[0], &path_src_attr[1]);
		} else if (JustFilename(path_src_attr))
		{
			file_name.replace(basedir_end_iter, file_name.cend(), path_src_attr.c_str());
			res = new GeneralServerGetResource(file_name, path_src_attr);
		} 

		if (res)
		{
			RegisterResource(res);
		}
	}
	
	src_parser.clear();
	return 0;
}*/

// private or not
Server::Resource* Server::FindResource(int method, const std::string& url)
{
	Resource* temp = nullptr;
	// auto transparent_comp = resources.key_comp();
	mResource::const_iterator found_result = resources.lower_bound(url);	
	if (found_result != resources.cend())
	{
		while(found_result != resources.cend() && 
			(strcmp(found_result->get()->url, url.c_str()) == 0)) // equivalent url
		{
			if ((*found_result)->method == method)
			{
				temp = (*found_result).get();
				break;
			}
			found_result++;
		}
	}

	return temp;
}

Server::~Server() noexcept
{
}

static std::string operator ""_s(const char* str, long unsigned int length)
{
	return std::string(str);
}

// =========================================================
// ==================== ConnectionInfo =====================
// =========================================================
// Server::ConnectionInfo::ConnectionInfo(const char* _url) 
// 	: session(nullptr)
// 	, postprocessor(nullptr)
// 	, connectiontype(HTTP::GET)
// 	, url(nullptr)
// 	, parser(nullptr)
// {
// 	assert(_url != NULL && "url is NULL!");
// 	url = strdupxx(_url);
// }


// Server::ConnectionInfo::ConnectionInfo(const char* _url,
// 								MHD_Connection* connection, 
// 								size_t post_buffer_size,
// 								MHD_PostDataIterator post_data_iterator)
// 	: session(nullptr)
// 	, postprocessor(nullptr)
// 	, connectiontype(HTTP::POST)
// 	, url(nullptr) 
// 	, parser(nullptr)
// {
// 	assert(_url != NULL && "url is NULL!");
// 	url = strdupxx(_url);

// 	/* postprocessor should return code, it is internal error or bad request */
// 	postprocessor =
// 		MHD_create_post_processor(connection, post_buffer_size,
// 								post_data_iterator, reinterpret_cast<void*>(this));

// 	if (postprocessor == NULL)
// 		throw std::runtime_error("Post processor create error!");
// }

// Server::ConnectionInfo::ConnectionInfo(
// 								const char* _url,
// 								MHD_Connection* conn,
// 								size_t post_buffer_size,
// 								ParsePostData _parser,
// 								void* cls)
// 	: session(nullptr)
// 	, postprocessor(nullptr)
// 	, connectiontype(HTTP::POST)
// 	, url(nullptr)
// 	, parser(nullptr)
// {
// 	assert(_url != NULL && "url is NULL!");
	
// 	url = strdupxx(_url);

// 	parser = new SimplePostProcessor(conn, post_buffer_size, _parser, cls);
// }

// MHD_Result Server::ConnectionInfo::PostProcess(
// 								const char* data,
// 								size_t size)
// {
// 	if (parser)
// 		return parser->parser(parser->conn, data, size);

// 	return MHD_post_process(postprocessor, data, size);
// }

// Server::ConnectionInfo::~ConnectionInfo()
// {
// 	if (postprocessor)
// 		MHD_destroy_post_processor(postprocessor);
// 	else if (parser)
// 		delete parser;

// 	if (url)
// 		delete[] url;

// }
// =========================================================
// ================= end ConnectionInfo ====================
// =========================================================


// =========================================================
// ================== SimplePostProcessor ==================
// =========================================================

// =========================================================
// ================== ending SimplePostProcessor ===========
// =========================================================

// #include "serverSIGNUP.cpp"


std::string_view Helper::dirname(std::string_view file_path)
{
    // . and .. url cannot relates to . and ..
    if (file_path[0] == '.')
    {
        return "/";
    }

    size_t pos_last_slash = file_path.rfind("/");
    return std::string_view(file_path.data(), pos_last_slash + 1);
};