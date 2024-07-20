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

class Helper
{
public:
	static std::string_view dirname(std::string_view file_path);
};


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
	static constexpr const char *BAD_REQUEST = "<html><body>Think next time before request</body></html>";

		static constexpr const char *ERROR_PAGE = "";

	static constexpr const char* EMPTY_RESPONSE = "";
	
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
			size_t* upload_data_size, void** con_cls)  = 0;

		virtual bool operator<(const Resource& that) const noexcept final;

		virtual bool operator==(const Resource& that) const noexcept final;

		virtual ~Resource() noexcept;

		typedef MHD_Result(ConfigurationCallback)(MHD_Connection*, void**);
		
		typedef void(ReleaseCallback)(void**);
		
		virtual ConfigurationCallback Configure;

		virtual ReleaseCallback Release;

	 	friend Server;
	public:
		const int method;
		const char*  url;
	private:
		bool configured;
	};

	/**
	 *  return 0 in success 
	 *  -1 in other cases
	*/
	int RegisterResource(Resource* resource);

	template<typename ...Args, 
		typename std::enable_if<std::is_same<Args, std::add_pointer_t<Server::Resource>>::value>::type...>
	int RegisterResources(Resource* resource, Args...);

	// int RegisterHTMLPage(const char* url, const char* file);

private:
	static ssize_t xxFileReaderCallback(void* cls, uint64_t pos, 
		char* buf, size_t max);

	static void xxContentReaderFreeCallback(void* cls);

	static typename std::remove_pointer_t<MHD_RequestCompletedCallback> CompletedConnectionCallback;
	
	/*class GeneralServerGetResource : public Resource
	{
	public:
		GeneralServerGetResource(const std::string& url, const std::string& _filename)
			: GeneralServerGetResource(url.c_str(), _filename.c_str())
		{};

		GeneralServerGetResource(std::string_view url, std::string_view _filename)
			: GeneralServerGetResource(url.data(), _filename.data())
		{};

		GeneralServerGetResource(const char* url, const char* _filename)
		 	: Resource(HTTP::GET, url)
		 	, filename(_filename)
		{};
		
		int RegistrationTimeCheck() const noexcept;

		MHD_Result operator()(void* cls, struct MHD_Connection* conn,
			const char* upload_data,
			size_t* upload_data_size) override;

		// ~GeneralServerGetResource() noexcept;
	private:
		const std::string filename;
	};
	*/

	Resource* FindResource(int method, const std::string& url);
	
	class ResourceComp
	{
	public:
		bool operator()(const std::unique_ptr<Resource>& lhs, 
			const std::unique_ptr<Resource>& rhs) const noexcept;

		bool operator()(const std::unique_ptr<Resource>& lhs,
			const std::string& url) const noexcept;

		bool operator()(const std::string& url,
			const std::unique_ptr<Resource>& lhs) const noexcept;

		bool operator()(const Resource& res,
			const std::unique_ptr<Resource>& rhs) const noexcept;

		bool operator()(const std::unique_ptr<Resource>& lhs,
			const Resource& res) const noexcept;

		using is_transparent = void;
	};

	typedef std::multiset<std::unique_ptr<Resource>,
		ResourceComp> mResource;
	 
	mResource resources;

	typedef MHD_Result(*ResourcePolicyCallback)(struct MHD_Connection* conn,
		const char* url, const char* method, 
		const char* version, const char* upload_data, 
		size_t upload_data_size);
	
public:
	static MHD_Result SendInternalErrResponse(MHD_Connection* connection);

	static MHD_Result SendNotFoundResponse(MHD_Connection* connection);

	static MHD_Result SendBadRequestResponse(MHD_Connection* connection);

	template <typename AuthT, typename... Args>
	void AddAuth(Args&&... args);

	typedef MHD_Result (ConfigurationCallback)(MHD_Connection*,
		const char*, const char*, void**);

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


#include "Server.inl"

#endif // SERVER_HPP_