#include "Server.hpp"

#include <time.h>

#include "sha256.h"

#include <iostream>
#include <algorithm>
#include <chrono>
#include <cassert>

#warning "ServerDB is public member!"


// const std::string Server::HashBasicAuthCode = 
// 		"d0949375b349696a1d9f14b2a9f119b396bd877ba0541f897a65557b8efe9305";
// // de facto Basic Authorization
// MHD_Result Server::BasicVerificate(struct MHD_Connection* connection)
// {	
// 	auto SendUnauthorized = [connection]() -> void{
// 		MHD_Response* response = MHD_create_response_from_buffer(strlen(Server::DENIED),
// 			(void*)Server::DENIED, MHD_RESPMEM_PERSISTENT); //  MHD_RESPMEM_MUST_COPY

// 		if (response == NULL)
// 		{
// 			std::cerr << "BasicVerificate(): create response error!\n";
// 			return ;
// 		}

// 		MHD_Result ret = MHD_queue_basic_auth_fail_response(connection, "realm", response);
// 		if (ret == MHD_NO)
// 		{
// 			std::cerr << "BasicVerificate(): queue response error!\n";
// 		}

// 		MHD_destroy_response(response);
// 	};

// 	char *user = nullptr;
// 	char *pass = nullptr;
// 	bool fail;
	
// 	user = MHD_basic_auth_get_username_password(connection, &pass);

// 	fail = ( (NULL == user) || (NULL == pass) ||
// 					 (HashBasicAuthCode != SHA256::hashString(pass)));
	
// 	if (NULL != user)
// 		MHD_free (user);
// 	if (NULL != pass)
// 		MHD_free (pass);
// 	if (fail)
// 	{
// 		SendUnauthorized();
// 		return MHD_NO;
// 	}

// 	return MHD_YES;
// }

// // de facto Digest Authorization
// MHD_Result Server::DGVerificate(struct MHD_Connection* connection)
// {
// 	enum MHD_Result ret;
// 	struct MHD_Response* response = nullptr;
// 	const char *password = "FORELITE";
// 	const char *realm = "auth_users@example.com";

// 	char *username = MHD_digest_auth_get_username (connection);
// 	if (username == NULL)
// 	{
// 		response = MHD_create_response_from_buffer(strlen (DENIED),
// 													 (void*)DENIED,
// 													 MHD_RESPMEM_PERSISTENT);
// 		ret = MHD_queue_auth_fail_response2 (connection,
// 											 realm,
// 											 OPAQUE,
// 											 response,
// 											 (int)MHD_NO,
// 											 MHD_DIGEST_ALG_SHA256);
// 		MHD_destroy_response(response);
// 		return MHD_NO;
// 	}

// 	ret = (MHD_Result) MHD_digest_auth_check2(connection,
// 										realm,
// 										username,
// 										password,
// 										300,
// 										MHD_DIGEST_ALG_SHA256);
// 	free(username);
// 	if ( (ret == MHD_INVALID_NONCE) ||
// 			 (ret == MHD_NO) )
// 	{
// 		response = MHD_create_response_from_buffer(strlen (DENIED),
// 													 (void*)DENIED,
// 													 MHD_RESPMEM_PERSISTENT);
// 		if (NULL == response)
// 			return MHD_NO;
// 		ret = MHD_queue_auth_fail_response2 (connection,
// 										realm,
// 										OPAQUE,
// 										response,
// 										(ret == MHD_INVALID_NONCE) ? MHD_YES : MHD_NO,
// 										MHD_DIGEST_ALG_SHA256);
// 		MHD_destroy_response(response);
// 		return MHD_NO;
// 	}

// 	return MHD_YES;
// }

/* may improve */
int Server::CombMethod(std::string_view finding_method) const
{
	return std::distance(methods.cbegin(),
		std::find_if(methods.cbegin(), methods.cend(), 
			[finding_method](std::string_view method)
			{ 
				return finding_method.compare(method) == 0; 
			}
		));
}

MHD_Result Server::SendNotFoundResponse(MHD_Connection* connection) const
{
	MHD_Response* not_found_response = 
		MHD_create_response_from_buffer(strlen(NOT_FOUND), 
			(void*)NOT_FOUND, MHD_RESPMEM_PERSISTENT);
	if (!not_found_response)
	{
		return MHD_NO;
	}

	MHD_Result ret = MHD_queue_response(connection, HTTP::NotFound, not_found_response);

	MHD_destroy_response(not_found_response);

	return ret;
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

	enum MHD_Result ret;
	// Session* session = nullptr;
	MHD_Connection* con_info = reinterpret_cast<MHD_Connection*>(*con_cls);
	
	if (!con_info)
	{
		// try
		// {
		// 	if (strcmp (method, MHD_HTTP_METHOD_POST) == 0) // if POST method
		// 	{
		// 		// MHD library parser of post data
		// 		// only above two content-type
		// 		const char* content_type = MHD_lookup_connection_value(
		// 			connection, MHD_HEADER_KIND, "Content-Type");
		// 		if (content_type == NULL)
		// 		{
		// 			session->STATUS_CODE = MHD_HTTP_BAD_REQUEST;
		// 			return SendPage(connection, session, Server::ERROR_PAGE, MHD_RESPMEM_PERSISTENT);
		// 		}
				
		// 		if (strcasecmp(content_type, MHD_HTTP_POST_ENCODING_FORM_URLENCODED) == 0 ||
		// 			strcasecmp(content_type, MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA) == 0)
		// 		{
		// 			// MHD post process
		// 			con_info = new Server::ConnectionInfo(url, connection, 
		// 				Server::POSTBUFFERSIZE, &IteratePostData);
		// 		} else 
		// 		{
		// 			con_info = new Server::ConnectionInfo(url, connection, 
		// 				Server::POSTBUFFERSIZE, &PostDataParser);
		// 		}
		// 	} else 
		// 	{
		// 		con_info = new Server::ConnectionInfo(url);
		// 	}

		// 	*con_cls = (void *) con_info;
		// } catch(...) // dont interested what exception we get
		// {
		// 	return MHD_NO;
		// }
		*con_cls = reinterpret_cast<void*>(connection);
		return MHD_YES;
	}

	// session = con_info->session;
	// session->start_ = std::chrono::system_clock::now();

	int method_number = backvalue_server->CombMethod(method);

	Resource* found_resource = backvalue_server->FindResource(
		method_number, url);

	if (found_resource == nullptr)
	{
		std::cerr << method << " " << url << ": resource not found!\n";
		return backvalue_server->SendNotFoundResponse(connection);
	}

	return found_resource->operator()(con_info, connection,
		version, upload_data, 
		upload_data_size);

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
{
}


Server::Resource::~Resource()
{
	if (url)
	{
		delete[] url; 
	}
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

int Server::RegisterHTMLPage(const char* url, const char* file)
{
	// internal src is added external skip
	// difference between /image.png and image.png
	// is /image.png is absolute file path but image.png is relative
	// we should classificate resources

	/* static*/ HTML::Parser src_parser;
	if (src_parser.init(url) == -1)
	{
		return -1;
	}

	// std::wstring path_src_attr;
	std::string path_src_attr;
	
	// const wchar_t* base_dir_path = basename(url);		
	// std::wstring file_name(base_dir_path); 
	const char* base_dir_path = basename(url);
	std::string file_name(base_dir_path); file_name.push_back('/');
	std::string::iterator basedir_end_iter = file_name.cend();
	while (!(path_src_attr = src_parser.parse()).emtpy())
	{
		// clasificate
		Resource* res = nullptr;
		if (path_src_attr[0] == '/')
		{
			res = new Resource(src_file.c_str() + 1, HTTP::GET);
		// } else if (strcmphead(src_file.c_str(), L"http") && src_file.c_str(), L"file"))
		} else if (strcmphead(src_file.c_str(), "http") && srccmphead(str_file.c_str(), "file"))
		{
			// file_name.append(L"/").append(src_file.c_str());
			file_name.replace(basedir_end_iter, file_name.cend(), src_file.c_str())
			res = new Resource(file_name.c_str(), HTTP::GET);
		} else 
		{
			// skip
		}

		if (res)
		{
			RegisterResourse(res);
		}
	}
	
	src_parser.clear();
	
}

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
