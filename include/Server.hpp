#ifndef SERVER_HPP_
#define SERVER_HPP_

#include "microhttpd.h"

#include <memory>
#include <set>
#include <string>

#include "ServerCore.hpp"
#include "ServerDB.hpp"
#include "Router.hpp"

// resource is entity of server
// #include "Resource.hpp"

namespace HTTP {
enum : uint16_t {
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
	typedef uint16_t http_methd_t;
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

	static char* strdupxx(std::string_view str);
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

	// const ServerCore& operator()() const { return server_core ; }
	
	// ServerCore& operator()() { return server_core; }

	Server& operator=(const Server&) = delete;
	Server(const Server&) = delete;

	static typename std::remove_pointer_t<MHD_AccessHandlerCallback> ReplyToConnection;

	// int CombMethod(std::string_view) const;

	static constexpr const char* SIGNUP_PAGE = CONCAT(HTML_SRC_PATH, "/sign_up.html");
	static constexpr const char* SIGNIN_PAGE = CONCAT(HTML_SRC_PATH, "/sign_in.html");
	static constexpr const char* SUCCESS_PAGE = CONCAT(HTML_SRC_PATH, "/chat.html");

	static constexpr const char* NOT_FOUND = "<html><body>Not found!</body></html>";
	static constexpr const char* INTERNAL_ERROR = "<html><body>Internal error!</body></html>";
	static constexpr const char *BAD_REQUEST = "<html><body>Think next time before request!</body></html>";
	static constexpr const char *NOT_ALLOWED_METHOD = "<html><body>Method not allowed!</body></html>";

	static constexpr const char *ERROR_PAGE = "";

	static constexpr const char* EMPTY_RESPONSE = "";
	
	~Server() noexcept;

	constexpr bool is_working() const { return m_working; };

	MHD_Result StartServer(bool is_blocked = false);

	template <typename... Args>
	void SaveConfiguration(Args... args);

	MHD_Result StopServer(bool easy = false); // easy or not

	static MHD_Result SendFile(struct MHD_Connection* conn,
		std::string_view page, uint16_t http_status_code = MHD_HTTP_OK);

	// only for syns webserver
	// struct RequestComplex
	// {
	// 	RequestComplex() = default;

	// 	void Release();

	// 	~RequestComplex() = default;

	// 	constexpr bool Filled() const { return is_filled; }

	// 	bool is_filled = false;
	// 	size_t upload_data_size = 0;
	// 	std::string uri;
	// 	std::string upload_data;
	// };

	class Resource
	{
	public:
		Resource(const char* _url);

		bool operator<(const Resource& that) const noexcept;

		bool operator==(const Resource& that) const noexcept;

		// GET method can not have body
		// template <typename STRUCT_HAD_QUERY_PARAMS_FIELDS>
		virtual MHD_Result DoGET( 
			MHD_Connection* conn, const char* uri);

		// virtual MHD_Result DoHEAD( 
		// 	MHD_Connection* conn, const char* uri);

		virtual MHD_Result DoPOST( 
			MHD_Connection* conn, const char* uri, const char* upload_data, size_t upload_data_size);

		// virtual MHD_Result DoPUT( 
		// 	MHD_Connection* conn, const char* uri, const char* upload_data, size_t upload_data_size);

		// virtual MHD_Result DoDELETE( 
		// 	MHD_Connection* conn, const char* uri, const char* upload_data, size_t upload_data_size);

		// virtual MHD_Result DoCONNECT( 
		// 	MHD_Connection* conn, const char* uri, const char* upload_data, size_t upload_data_size);

		// virtual MHD_Result DoOPTIONS( 
		// 	MHD_Connection* conn, const char* uri, const char* upload_data, size_t upload_data_size);

		// virtual MHD_Result DoTRACE( 
		// 	MHD_Connection* conn, const char* uri, const char* upload_data, size_t upload_data_size);

		// virtual MHD_Result DoPATCH( 
		// 	MHD_Connection* conn, const char* uri, const char* upload_data, size_t upload_data_size);

		/**
		 * Required confiquration and 
		 * property of connection 
		 * and user takes responsibility to answer 
		 * if it failed! Return is_success
		 * */
		virtual MHD_Result Required(
			struct MHD_Connection* conn, const char* uri, const char* method) const noexcept 
		{ return MHD_YES; };

		virtual ~Resource() noexcept;

	 	friend Server;
	public:
		const char*           url;
	private:
		bool configured = false;
	};

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

	/**
	 *  return 0 in success 
	 *  -1 in other cases
	*/
	int RegisterResource(Resource* resource);

	template<typename ...Args, 
		typename std::enable_if<std::is_same<Args, std::add_pointer_t<Server::Resource>>::value>::type...>
	int RegisterResources(Resource* resource, Args&&...);

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

	Resource* FindResource(const std::string& url);

	// typedef std::multiset<std::unique_ptr<Resource>,
	// 	ResourceComp> mResource;
	 
	// mResource resources;

	typedef MHD_Result(*ResourcePolicyCallback)(struct MHD_Connection* conn,
		const char* url, const char* method, 
		const char* version, const char* upload_data, 
		size_t upload_data_size);

public:
	static MHD_Result SendInternalErrResponse(MHD_Connection* connection);

	static MHD_Result SendNotFoundResponse(MHD_Connection* connection);

	static MHD_Result SendBadRequestResponse(MHD_Connection* connection);

	static MHD_Result SendMethodNotAllowedResponse(MHD_Connection* connection);

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

	bool m_working = false;

	ServerCore server_core;

	// RequestComplex request_complex;

	std::function<MHD_Result()> ConfigurationCallback;

	Router<Resource*> m_router;
};

#include "Resource.inl"

#include "Server.inl"

#endif // SERVER_HPP_