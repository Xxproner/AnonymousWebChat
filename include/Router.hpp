#ifndef ROUTER_HPP
#define ROUTER_HPP

// #include "microhttpd.h"

#include <memory>
#include <type_traits>

#include "boost/property_tree/ptree.hpp"
#include "Resource.hpp"

namespace pt = boost::property_tree;

template <typename T>
struct const_ref_details_
{
	using type = typename std::reference_wrapper<const T>::type;


	using clear_T = typename std::remove_reference<T>::type;
};

template <typename EndpointData_t> // default contructible
class Router
{
public:

	static_assert(std::is_trivially_constructible_v<EndpointData_t>);
	// router owns endpointdata 
	// then we need to avoid copy ???

	using Routers_t = pt::basic_ptree<std::string, EndpointData_t>;

	Router() = default;

	Router(const EndpointData_t& root_data);

	// template <typename EndpointData_t
	// 	std::enable_if< 
	// 		std::is_invocable_v<
	// 			EndpointD_comp, std::const_ref_details_<EndpointData_t>::type, std::const_ref_details_<EndpointData_t>::type
	// 		>  
	// 	>
	// >
	EndpointData_t* FindNearestRoute(
		const typename Routers_t::key_type& url);

	template <typename... Args>
	int AddRoute(const typename Routers_t::key_type& url, Args&&... args); // , const RouteConfig& route_conf = RouteConfig);

	// AddStaticRoute(const std::string& url);

private:
	Routers_t m_router;
};


#include "Router.inl"

#endif // ROUTER_HPP