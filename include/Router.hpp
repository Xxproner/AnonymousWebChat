#ifndef ROUTER_HPP
#define ROUTER_HPP

#include <memory>
#include <type_traits>
#include <optional>
#include <memory>

#include "boost/property_tree/ptree.hpp"

namespace pt = boost::property_tree;

template <typename T>
struct const_ref_details_
{
	using type = typename std::reference_wrapper<const T>::type;


	using clear_T = typename std::remove_reference<T>::type;
};

template <typename Ptr_EndpointData_t, typename Incompleted = void>
class Router // for pointers
{
	// I am confused about Router class owns performed data to it
	// and we can meet problem: invalid pointers
public:

	using EndpointData_t = typename std::remove_pointer<Ptr_EndpointData_t>::type;

	using Routers_t = pt::basic_ptree<std::string, std::shared_ptr<EndpointData_t>>;

	typedef boost::property_tree::iptree ptree;

	Router(EndpointData_t* root_data) noexcept;

	std::pair<std::string, EndpointData_t*>
	FindNearestRoute(const typename Routers_t::key_type& url) noexcept(false);

	std::pair<std::string, const EndpointData_t*>
	FindNearestRoute(const typename Routers_t::key_type& url) const noexcept(false);

	EndpointData_t* FindRoute(
		const typename Routers_t::key_type& url) noexcept(false);

	const EndpointData_t* FindRoute(
		const typename Routers_t::key_type& url) const noexcept(false);

	int AddRoute(const typename Routers_t::key_type& url, EndpointData_t* endpoint_data) noexcept(false); 

	template <typename... Args>
	int AddRoute(const typename Routers_t::key_type& url, Args&&... args) noexcept(false);

private:
	Routers_t m_router;	
};

template <typename EndpointData_t> 
class Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>
{

	static_assert(!std::is_same<EndpointData_t, bool>::value, "Reject boolean type!");
	static_assert(std::is_move_constructible<EndpointData_t>::value || 
			std::is_trivially_move_constructible<EndpointData_t>::value, "Reject not movable type!");
	static_assert(std::is_move_assignable<EndpointData_t>::value ||
			std::is_trivially_move_assignable<EndpointData_t>::value, "Reject not movable type!");
public:

	// static_assert(std::is_same<path_type, std::string>::value, "Always true");


	// router owns endpointdata 
	// then we need to avoid copy ???


	typedef boost::property_tree::iptree ptree;
	using Routers_t = pt::basic_ptree<std::string, std::optional<EndpointData_t>>;

	// if we want default ctor
	// then find nearest route may fail
	// cause no endpoint data in the all tree
	// Router() = default; !

	Router(EndpointData_t root_data);

	// template <typename EndpointData_t
	// 	std::enable_if< 
	// 		std::is_invocable_v<
	// 			EndpointD_comp, std::const_ref_details_<EndpointData_t>::type, std::const_ref_details_<EndpointData_t>::type
	// 		>  
	// 	>
	// >
	std::pair<std::string, 
		std::optional<EndpointData_t>&>
	FindNearestRoute(const typename Routers_t::key_type& url) noexcept(false);

	std::pair<std::string, 
		const std::optional<EndpointData_t>&>
	FindNearestRoute(const typename Routers_t::key_type& url) const noexcept(false);

	std::optional<EndpointData_t>& FindRoute(
		const typename Routers_t::key_type& url) noexcept(false);

	const std::optional<EndpointData_t>& FindRoute(
		const typename Routers_t::key_type& url) const noexcept(false);
	
	int AddRoute(const typename Routers_t::key_type& url, EndpointData_t endpoint_data) noexcept(false);

	template <typename... Args>
	int AddRoute(const typename Routers_t::key_type& url, Args&&... args) noexcept(false); // , const RouteConfig& route_conf = RouteConfig);

	// AddStaticRoute(const std::string& url);

private: // methods


private: // members
	Routers_t m_router;
};


#include "Router.inl"

#endif // ROUTER_HPP