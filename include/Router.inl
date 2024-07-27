#include <vector>
#include <string_view>
#include <string>

class UrlUtils {
public:
	static std::vector<std::string_view>
		Split(std::string_view spliting_string);

	static std::vector<std::string>
		SplitStream(const std::string& spliting_stream);
};

// template <typename Ptr_EndpointData_t>
// Router<Ptr_EndpointData_t>::Router(const Router::EndpointData_t* endpoint_data)
// 	: m_router()
// {
// 	// std::cerr << "Router for pointers owns data. Be careful with valid pointer!\n";
// 	m_router.data().reset(endpoint_data);
// };


// template <typename Ptr_EndpointData_t> 
// int Router<Ptr_EndpointData_t>::AddRoute(const typename Routers_t::key_type& url,
// 	const Router::EndPointData_t* endpoint_data)
// {
// 	// url can determine either directory or path 
// 	auto route_pieces = UrlUtils::Split(url);

// 	if (route_pieces[0].compare("/") != 0)
// 	{
// 		// error
// 		return -1;
// 	}

// 	Routers_t* subtree = &m_router;
// 	for (size_t k = 1; k < route_pieces.size() - 1; ++k)
// 	{
// 		// get child of property tree
// 		try {
// 			// if exceptions was thrown subtree not modified?
// 			subtree = 
// 				&subtree->get_child(route_pieces[k].data());

// 		} catch(const pt::ptree_bad_path&)
// 		{
// 			// path not found
// 			// then should add
// 			while (k < route_pieces.size() - 1)
// 			{
// 				subtree = &subtree->put(route_pieces[k].data(), std::unique_ptr<EndpointData_t>{nullptr}/*, Translator*/);
// 				++k;
// 			}
// 		}	
// 	}

// 	subtree->put(route_pieces.crbegin()->data(), std::unique_ptr<EndpointData_t>{endpoint_data});
// 	return 0;
// };


// /**
//  * add directory or specific `file` aka .html */
// template <typename Ptr_EndpointData_t>
// template <typename... Args> 
// int Router<Ptr_EndpointData_t>::AddRoute(const typename Routers_t::key_type& url, Args&&... args)
// {
// 	// url can determine either directory or path 

// 	static_assert(std::is_constructible_v<EndpointData_t, Args...>,
// 		"Data type must be constructible with args pack!");

// 	// if we have new operator in endpoint data_t call it
// 	// else : 

// 	std::allocator<EndpointData_t> alloc;
// 	EndpointData_t* temp = std::allocator_traits::allocate(alloc, 1);
// 	std::allocator_traits::construct(alloc, temp, std::forward<Args>(args)...);

// 	return AddRoute(url, temp);
// };

// template <typename Ptr_EndpointData_t
// // 	std::enable_if< 
// // 		std::is_invocable_v<
// // 			EndpointD_comp, std::const_ref<EndpointData_t>::type, std::const_ref<EndpointData_t>::type
// // 		>//, bool
// // 	>//, = true
// >	
// typename Router::EndpointData_t& Router<Ptr_EndpointData_t>::FindRoute(
// 	const typename Routers_t::key_type& url) noexcept(false)
// {
// 	auto route_pieces = 
// 		UrlUtils::Split(url);

// 	if (route_pieces[0].compare("/") != 0)
// 	{
// 		// url error
// 		throw std::runtime_error("Url must be relative ( `/...' )!");
// 		// return nullptr;
// 	}

// 	Routers_t* subtree = &m_router;
// 	for (size_t k = 0; k < route_pieces.size(); ++k)
// 	{
// 		subtree = 
// 			&subtree->get_child(route_pieces[k].data());
// 	}

// 	return *subtree->data(); // guaranteed valid value
// };

// template <typename Ptr_EndpointData_t
// // 	std::enable_if< 
// // 		std::is_invocable_v<
// // 			EndpointD_comp, std::const_ref<EndpointData_t>::type, std::const_ref<EndpointData_t>::type
// // 		>//, bool
// // 	>//, = true
// >	
// std::pair<std::string, 
// 	typename std::add_lvalue_reference<EndpointData_t>::type>
// Router<Ptr_EndpointData_t>::FindNearestRoute(
// 		const typename Routers_t::key_type& url)
// {
// 	auto route_pieces = 
// 		UrlUtils::Split(url);

// 	if (route_pieces[0].compare("/") != 0)
// 	{
// 		// url error
// 		throw std::runtime_error("Url must be relative ( `/...' )!");
// 		// return nullptr;
// 	}

// 	std::string available_route ;
// 	Routers_t* subtree = &m_router;

// 	for (size_t k = 0; k < route_pieces.size(); ++k)
// 	{
// 		try 
// 		{
// 			subtree = 
// 				&subtree->get_child(route_pieces[k].data());

// 			available_route.append(route_pieces[k]);
// 		} catch (const pt::ptree_bad_path&)
// 		{

// 		}
// 	}

// 	return std::make_pair(available_route, subtree->data().value());
// };

// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================

template <typename EndpointData_t>
Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>::Router(
	const EndpointData_t& endpoint_data)
	: m_router()
{
	m_router.data() = endpoint_data;
};

template <typename EndpointData_t>
int Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>::AddRoute(
	const typename Routers_t::key_type& url, EndpointData_t endpoint_data)
{
	// url can determine either directory or path 

	auto route_pieces = UrlUtils::Split(url);

	if (!route_pieces[0].empty())
	{
		// error
		throw std::runtime_error("Url must be relative ( `/...' )!");
	}

	Routers_t* subtree = &m_router;

	for (size_t k = 1; k < route_pieces.size() - 1; ++k)
	{
		// get child of property tree
		try {
			// if exceptions was thrown subtree not modified?
			subtree = 
				&subtree->get_child(route_pieces[k].data());

		} catch(const pt::ptree_bad_path&)
		{
			// path not found
			// then should add
			while (k < route_pieces.size() - 1)
			{
				subtree = &subtree->put(route_pieces[k].data(), std::optional<EndpointData_t>{std::nullopt}/*, Translator*/);
				++k;
			}
		}
	}

	// if resource exists then it changes
	subtree->put(route_pieces.crbegin()->data(), std::optional<EndpointData_t>{std::forward<EndpointData_t>(std::move(endpoint_data))});
	
	return 0;
};

/**
 * add directory or specific `file` aka .html */
template <typename EndpointData_t>
template <typename... Args> 
int Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>::AddRoute(
	const typename Routers_t::key_type& url, Args&&... args)
{
	// url can determine either directory or path 

	static_assert(std::is_constructible_v<EndpointData_t, Args...>,
		"Data type must be constructible with args pack!");

	return AddRoute(url, {std::forward<Args>(args)...}); // copy elision
};

template <typename EndpointData_t
// 	std::enable_if< 
// 		std::is_invocable_v<
// 			EndpointD_comp, std::const_ref<EndpointData_t>::type, std::const_ref<EndpointData_t>::type
// 		>//, bool
// 	>//, = true
>	
std::optional<EndpointData_t>& Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>::FindRoute(
	const typename Routers_t::key_type& url) noexcept(false)
{
	auto route_pieces = 
		UrlUtils::Split(url);

	if (!route_pieces[0].empty())
	{
		// url error
		throw std::runtime_error("Url must be relative ( `/...' )!");
		// return nullptr;
	}

	Routers_t* subtree = &m_router;
	for (size_t k = 0; k < route_pieces.size(); ++k)
	{
		subtree = 
			&subtree->get_child(route_pieces[k].data());
	}

	return subtree->data();
};

template <typename EndpointData_t
// 	std::enable_if< 
// 		std::is_invocable_v<
// 			EndpointD_comp, std::const_ref<EndpointData_t>::type, std::const_ref<EndpointData_t>::type
// 		>//, bool
// 	>//, = true
>	
const std::optional<EndpointData_t>& Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>::FindRoute(
	const typename Routers_t::key_type& url) const noexcept(false)
{
	auto route_pieces = 
		UrlUtils::Split(url);

	if (!route_pieces[0].empty())
	{
		// url error
		throw std::runtime_error("Url must be relative ( `/...' )!");
		// return nullptr;
	}

	Routers_t* subtree = &m_router;
	for (size_t k = 0; k < route_pieces.size(); ++k)
	{
		subtree = 
			&subtree->get_child(route_pieces[k].data());
	}

	return subtree->data();
};


template <typename EndpointData_t
// 	std::enable_if< 
// 		std::is_invocable_v<
// 			EndpointD_comp, std::const_ref<EndpointData_t>::type, std::const_ref<EndpointData_t>::type
// 		>//, bool
// 	>//, = true
>	
std::pair<std::string, 
	std::optional<EndpointData_t>&>
Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>::FindNearestRoute(
		const typename Routers_t::key_type& url)
{
	auto route_pieces = 
		UrlUtils::Split(url);

	if (!route_pieces[0].empty())
	{
		// url error
		throw std::runtime_error("Url must be relative ( `/...' )!");
	}

	std::string available_route{"/"};
	Routers_t* subtree = &m_router;

	for (size_t k = 1; k < route_pieces.size(); ++k)
	{
		try
		{
			subtree = 
				&subtree->get_child(route_pieces[k].data());

			available_route.append(route_pieces[k]);
			if (k != route_pieces.size() - 1)
			{
				available_route.push_back('/');
			}

		} catch (const pt::ptree_bad_path&)
		{
			break;
		}
	}

	return {available_route, subtree->data()};
};


template <typename EndpointData_t
// 	std::enable_if< 
// 		std::is_invocable_v<
// 			EndpointD_comp, std::const_ref<EndpointData_t>::type, std::const_ref<EndpointData_t>::type
// 		>//, bool
// 	>//, = true
>	
std::pair<std::string, 
	const std::optional<EndpointData_t>&>
Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>::FindNearestRoute(
		const typename Routers_t::key_type& url) const
{
	auto route_pieces = 
		UrlUtils::Split(url);

	if (!route_pieces[0].empty())
	{
		// url error
		throw std::runtime_error("Url must be relative ( `/...' )!");
	}

	std::string available_route{"/"};
	Routers_t* subtree = &m_router;

	for (size_t k = 1; k < route_pieces.size(); ++k)
	{
		try
		{
			subtree = 
				&subtree->get_child(route_pieces[k].data());

			available_route.append(route_pieces[k]);
			if (k != route_pieces.size() - 1)
			{
				available_route.push_back('/');
			}

		} catch (const pt::ptree_bad_path&)
		{
			break;
		}
	}

	return {available_route, subtree->data()};
};
