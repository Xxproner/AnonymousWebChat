#ifndef SERVER_HPP_
#define SERVER_HPP_

#include "microhttpd.h"

#include <memory>
#include <set>
#include <string>

#include "ServerCore.hpp"
#include "ServerDB.hpp"

namespace HTTP
{
	enum {
		GET = 0,
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

// =========================================================
// ================== ResourceHash =========================
// =========================================================

// template <>
// struct std::hash<std::pair<int, std::string>>
// {
// 	size_t operator()(const std::pair<int, std::string>& instance) const noexcept
// 	{
// 		auto CeaserAlgo = [](std::string& str, int step)
// 		{
// 	#warning "Overflow is possible"
// 			std::transform(str.cbegin(), str.cend(), str.begin(),
// 				[step](char ch){ return ch += step; });
// 		};

// 		std::string copy_string = instance.second;
// 		CeaserAlgo(copy_string, instance.first);

// 		return std::hash<std::string>()(copy_string);
// 	};
// };


// =========================================================
// ================== ending ResourceHash ==================
// =========================================================


class Server
{
public:
	typedef MHD_Result(BasicAuthInterface)(
		MHD_Connection*, const std::string& username, 
		const std::string& passw, const std::string& realm);
	class BasicAuth_t;

	typedef MHD_Result(DigestAuthInterface)(
		MHD_Connection*, const std::string& username, 
		const std::string& passw, const std::string& realm, 
		const std::string& opaque, enum MHD_DigestAuthAlgorithm alg, 
		unsigned int nonce_timeout);
	class DigestAuth_t;

	/* imcompleted type! */
	typedef MHD_Result(JWTAuthInterface)(
		MHD_Connection* conn);
	class JWT_t;

	static constexpr std::array<const char*, 9> methods{
		"GET", "HEAD", "POST", "PUT",  "DELETE", 
		"CONNECT", "TRACE", "OPTIONS", "PATCH"};

	template <typename... Args>
	Server(
		  MHD_FLAG exec_flags
		, uint16_t port
		, MHD_AcceptPolicyCallback acceptCallback
		, void* param2
		, Args... args);

	const ServerCore& operator()() const { return server_core ; }
	
	ServerCore& operator()() { return server_core; }

	Server& operator=(const Server&) = delete;
	Server(const Server&) = delete;

	static typename std::remove_pointer_t<MHD_AccessHandlerCallback> ReplyToConnection;

	int CombMethod(std::string_view) const;

	static constexpr const char* SIGNUP_PAGE = CONCAT(HTML_SRC_PATH, "/sign_up.html");
	static constexpr const char* SIGNIN_PAGE = CONCAT(HTML_SRC_PATH, "/sign_in.html");
	static constexpr const char* SUCCESS_PAGE = CONCAT(HTML_SRC_PATH, "/chat.html");

	static constexpr const char* NOT_FOUND = "<html><body>Not found!</body></html>";
	static constexpr const char* INTERNAL_ERROR = "<html><body>Internal error!</body></html>";
	static constexpr const char *ERROR_PAGE = "";

	static constexpr const char* EMPTY_RESPONSE = "";

	static constexpr const char* MY_SERVER = "kinkyServer";
	~Server() noexcept;

	constexpr bool is_working() const { return working; };

	static MHD_Result SendFile(struct MHD_Connection* conn,
		std::string_view page, uint16_t http_status_code = MHD_HTTP_OK);

	class Resource
	{
	public:
		Resource(int _method, const char* url);

		virtual MHD_Result operator()(void* cls, struct MHD_Connection* conn,
			const char* upload_data,
			size_t* upload_data_size)  = 0;

		virtual bool operator<(const Resource& that) const noexcept final
		{
			return strcmp(url, that.url) < 0;
		}

		virtual bool operator==(const Resource& that) const noexcept final
		{
			return !(*this < that) && !(that < *this);
		}

		// bool operator<(const std::string);

		virtual ~Resource() noexcept;
	public:
		const int method;
		const char*  url;
	};

	int RegisterResource(Resource* resource);

	template<typename ...Args, 
		typename std::enable_if<std::is_same<Args, std::add_pointer_t<Server::Resource>>::value>::type...>
	int RegisterResource(Resource* resource, Args...);

	int RegisterHTMLPage(const char* url, const char* file);

private:
	static ssize_t xxFileReaderCallback(void* cls, uint64_t pos, 
		char* buf, size_t max);

	static void xxContentReaderFreeCallback(void* cls);

	class GeneralServerGetResource : public Resource
	{
	public:
		GeneralServerGetResource(const char* url)
		 	: Resource(HTTP::GET, url)
		{}
		
		MHD_Result operator()(void* cls, struct MHD_Connection* conn,
			const char* upload_data,
			size_t* upload_data_size) override;

		// ~GeneralServerGetResource() noexcept;

	};

	// typedef std::pair<int, std::unique_ptr<Resource>> ResourceonMethod;

	Resource* FindResource(int method, const std::string& url) ;
	
	// TODO: registation directory
	class ResourceComp
	{
	public:
		bool operator()(const std::unique_ptr<Resource>& lhs, 
			const std::unique_ptr<Resource>& rhs) const noexcept
		{
			return *lhs.get() < *rhs.get();
		};

		bool operator()(const std::unique_ptr<Resource>& lhs,
			const std::string& url) const noexcept
		{
			return strcmp(lhs.get()->url, url.c_str()) < 0;
		}

		bool operator()(const std::string& url,
			const std::unique_ptr<Resource>& lhs) const noexcept
		{
			return strcmp(url.c_str(), lhs.get()->url) < 0;
		}

		bool operator()(const Resource& res,
			const std::unique_ptr<Resource>& rhs) const noexcept
		{
			return strcmp(res.url, rhs.get()->url) < 0;
		}

		bool operator()(const std::unique_ptr<Resource>& lhs,
			const Resource& res) const noexcept
		{
			return strcmp(lhs.get()->url, res.url) < 0;
		}

		using is_transparent = void;
	};

	typedef std::multiset<std::unique_ptr<Resource>,
		ResourceComp> mResource;
	 
	mResource resources;

	typedef MHD_Result(*ResourcePolicyCallback)(struct MHD_Connection* conn,
		const char* url, const char* method, 
		const char* version, const char* upload_data, 
		size_t upload_data_size);
	
	static MHD_Result SendInternalErrResponse(MHD_Connection* connection) ;

	static MHD_Result SendNotFoundResponse(MHD_Connection* connection) ;
public:

	template <typename AuthT, typename... Args>
	void AddAuth(Args&&... args);

private:
	static constexpr const char* DENIED =
		"<html><head><title>libmicrohttpd demo</title></head><body>Access denied</body></html>";

	std::function<MHD_Result(MHD_Connection*)> Auth;

	static BasicAuthInterface BasicAuth;

	static DigestAuthInterface DigestAuth;

	static JWTAuthInterface JWTAuth;

private:	
	bool working = false;

	ServerCore server_core;
};


template <typename... Args>
	Server::Server(
		  MHD_FLAG exec_flags
		, uint16_t port
		, MHD_AcceptPolicyCallback accessCallback
		, void* param1
		, Args... args)
{

	server_core.easy_start(exec_flags, port, accessCallback, param1,
		&ReplyToConnection, reinterpret_cast<void*>(this), args...);

	working = true;
}


template<typename ...Args, 
	typename std::enable_if<std::is_same<Args, std::add_pointer_t<Server::Resource>>::value>::type...>
int Server::RegisterResource(Resource* res, Args... ress)
{
	int return_code = RegisterResource(res);
	return_code |= RegisterResource(ress...);
	return return_code;
}


template <typename AuthT, typename... Args>
void Server::AddAuth(Args&&... args) 
{
	if constexpr(std::is_same_v<AuthT, BasicAuth_t>)
	{
		Auth = std::bind(BasicAuth, std::placeholders::_1, std::forward<Args>(args)...);
	} else if (std::is_same_v<AuthT, DigestAuth_t>)
	{
		Auth = std::bind(DigestAuth, std::placeholders::_1, std::forward<Args>(args)...);
	} else if (std::is_same_v<AuthT, JWT_t>)
	{
		Auth = std::bind(JWTAuth, std::placeholders::_1, std::forward<Args>(args)...);
	} else 
	{
		// static_assert(false, "Not available auth type!");
	}
}


#endif // SERVER_HPP_