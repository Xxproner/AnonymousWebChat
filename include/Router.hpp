#ifndef ROUTER_HPP
#define ROUTER_HPP

// #include "microhttpd.h"

#include <memory>

#include "boost/property_tree/pthree.hpp"
#include "Resource.hpp"

using namespace pt = boost::property_tree;

class Router
{
public:
	using Routers_t = pt::basic_ptree<std::string, EndpointData>;

	// Router(const Routers_t::key_type& domain);

	struct EndpointData
	{
		// EndpointData();

		EndpointData(HTTP_METHD_t method, const char* url);

		std::unique_ptr<Resource> endp_resource;

		// Routers_t::key_type uri;
	};

	struct RouteConfig
	{

	};

	Resource* FindRoute(
		const Routers_t::key_type& url,
		HTTP_METHD_t,
		);

	unknown_t AddRoute(const std::string& url); // , const RouteConfig& route_conf = RouteConfig);

	unknown_t AddStaticRoute(const std::string& url);

private:
	Routers_t m_router;
};




#endif // ROUTER_HPP