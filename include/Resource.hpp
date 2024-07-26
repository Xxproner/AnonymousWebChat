#ifndef RESOURCE_HPP
#define RESOURCE_HPP

#include <string.h>

#include <memory>
#include <string>

#include "microhttpd.h"

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


class Resource
{
public:
	Resource(HTTP::http_methd_t _method, const char* url);

	virtual MHD_Result operator()(struct MHD_Connection* conn,
		const char* upload_data,
		size_t upload_data_size) = 0;

	virtual bool operator<(const Resource& that) const noexcept final;

	virtual bool operator==(const Resource& that) const noexcept final;

	/**
	 * Required confiquration and 
	 * property of connection 
	 * and user takes responsibility to answer 
	 * if it failed! Return is_success
	 * */
	virtual MHD_Result Required(struct MHD_Connection*) const noexcept { return MHD_YES; };

	virtual ~Resource() noexcept;

	// typedef MHD_Result(ConfigurationCallback)(MHD_Connection*, void**);
	
	// typedef void(ReleaseCallback)(void**);
	
	// virtual ConfigurationCallback Configure;

	// virtual ReleaseCallback Release;

 	// friend Server;
public:
	const HTTP::http_methd_t method;
	const char*           url;
// private:
	// bool configured;
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

#include "Resource.inl"

#endif // RESOURCE_HPP