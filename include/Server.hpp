#ifndef SERVER_HPP_
#define SERVER_HPP_

#include "microhttpd.h"

#include <mutex>
#include <forward_list>
#include <deque>

#include "ServerCore.hpp"
#include "ServerDB.hpp"
#include "Participant.hpp"


namespace HTTP
{
	enum {
		GET,
		HEAD,
		POST,
		PUT,
		DELETE,
		CONNECT,
		OPTIONS,
		TRACE,
		PATCH
	};

	// Here we only support HTTP/1.1
	enum HttpVersion { // class
		HTTP_0_9 = 9,
		HTTP_1_0 = 10,
		HTTP_1_1 = 11,
		HTTP_2_0 = 20
	};


	enum HttpStatusCode { // class
		Continue = 100,
		SwitchingProtocols = 101,
		EarlyHints = 103,
		Ok = 200,
		Created = 201,
		Accepted = 202,
		NonAuthoritativeInformation = 203,
		NoContent = 204,
		ResetContent = 205,
		PartialContent = 206,
		MultipleChoices = 300,
		MovedPermanently = 301,
		Found = 302,
		NotModified = 304,
		BadRequest = 400,
		Unauthorized = 401,
		Forbidden = 403,
		NotFound = 404,
		MethodNotAllowed = 405,
		RequestTimeout = 408,
		Conflict = 409,
		ImATeapot = 418,
		InternalServerError = 500,
		NotImplemented = 501,
		BadGateway = 502,
		ServiceUnvailable = 503,
		GatewayTimeout = 504,
		HttpVersionNotSupported = 505
	};
}; // namespace HTTP


#define CONCAT(a, b) (a"" b) // For external macros

typedef MHD_Result (*ParsePostData)(
	MHD_Connection* conn, 
	const char* data, 
	size_t data_size);

struct SimplePostProcessor 
{
	char* buffer;
	size_t post_buffer_size;
	ParsePostData parser;
	MHD_Connection* conn;
	void* cls;

	SimplePostProcessor(struct MHD_Connection* _conn,
		size_t _post_buffer_size,
		ParsePostData _parser,
		void* _cls);

	// DELETED_COPY_CTOR(SimplePostProcessor)

	~SimplePostProcessor() noexcept;
};


class Server
{
public:
	template <typename... Args>
	Server(
			MHD_FLAG exec_flags
		, uint16_t port
		, ServerCore::MHD_AcceptPolicyCallback* acceptCallback
		, void* param1
		, ServerCore::MHD_AccessHandlerCallback* accessCallback
		, void* param2
		, Args... args);

	static MHD_Result ReplyToOptionsMethod(MHD_Connection* connection);
			
	static MHD_Result BasicVerificate(struct MHD_Connection* connection);

	static MHD_Result DGVerificate(struct MHD_Connection* connection);

	Session* GetSession (struct MHD_Connection *connection);

	void ExpireSession() noexcept;

	// access to serverCore of server
	const ServerCore& operator()() const { return server_core ; }
	
	ServerCore& operator()() { return server_core; }

	Server& operator=(const Server&) = delete;
	Server(const Server&) = delete;

	MHD_AcceptPolicyCallback ReplyToConnection;

	// chat configuration :
	// ===========================================
	constexpr static size_t POSTBUFFERSIZE = 512;
	constexpr static size_t MAXNAMESIZE = 30;
	constexpr static size_t MAXANSWERSIZE = 512;
	constexpr static size_t MAXMEMBERSNUMBER = 10;
	constexpr static size_t MAXACTIVEMEMBERS = 5; 

	// ===========================================

	static constexpr const char* PATH_TO_DB = CONCAT(DB_PATH, "/users.db");
	static constexpr const char* SIGNUP_PAGE = CONCAT(HTML_SRC_PATH, "/sign_up.html");
	static constexpr const char* SIGNIN_PAGE = CONCAT(HTML_SRC_PATH, "/sign_in.html");
	static constexpr const char* SUCCESS_PAGE = CONCAT(HTML_SRC_PATH, "/chat.html");

	static constexpr const char* NOT_FOUND_ERROR = "";
	static constexpr const char *ERROR_PAGE = "";

	static constexpr const char* EMPTY_RESPONSE = "";
	static constexpr const char* DENIED = "<html><body>Fail authorization!</body></html>";

	static constexpr const char* MY_SERVER = "kinkyServer";
	~Server() noexcept;

	serverDB partpants_list; // thread safety

	constexpr bool is_working() const { return working; };

	class Resource
	{
	public:
		virtual MHD_Result operator()(void* cls, struct MHD_Connection* conn,
			const char* url, const char* method,
			const char* version, const char* upload_data,
			size_t* upload_data_size, void** con_cls) = 0;
	};

private:
	struct ResourceHash
	{
		size_t operator()(const std::pair<int, std::string>& instance);
	};


	typedef MHD_Result(*ResourcePolicyCallback)(struct MHD_Connection* conn,
		const char* url, const char* method, 
		const char* version, const char* upload_data, 
		size_t upload_data_size);

	// only for post method
	std::unordered_map<std::pair<int, std::string>, 
		> resources;

	int RegisterResource(int method, std::string_view url, 
		MHD_Response* response);

private:	
	bool working = false;

	static const std::string HashBasicAuthCode;

	static constexpr const char* OPAQUE = "11733b200778ce33060f31c9af70a870ba96ddd4";

	ServerCore server_core;
  	std::forward_list<struct Session*> sessionsList;
};

template <typename... Args>
	Server::Server(
		  MHD_FLAG exec_flags
		, uint16_t port
		, ServerCore::MHD_AcceptPolicyCallback* acceptCallback
		, void* param1
		, ServerCore::MHD_AccessHandlerCallback* accessCallback
		, void* param2
		, Args... args)
{

	server_core.easy_start(exec_flags, port, acceptCallback, 
		param1, accessCallback, param2, args...);

	if (partpants_list.open(PATH_TO_DB))
		throw std::runtime_error("Server::Server(): open database error!");

	working = true;
}

#endif // SERVER_HPP_