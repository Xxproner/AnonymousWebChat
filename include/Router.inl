#include <vector>
#include <string_view>
#include <string>

class UrlUtils {
public:
	static std::vector<std::string>
		Split(std::string_view spliting_string);

	static std::vector<std::string>
		SplitStream(const std::string& spliting_stream);

	static void 
		CheckUrlCorrectnessThrow_V(const std::string& url) noexcept(false);

	static bool 
		CheckUrlCorrectness(const std::string& url) noexcept;
};

template <typename Ptr_EndpointData_t, typename Enable>
Router<Ptr_EndpointData_t, Enable>::Router(
	typename Router<Ptr_EndpointData_t, Enable>::EndpointData_t* root_data) noexcept
	: m_router(std::shared_ptr<EndpointData_t>{root_data})
	// : m_router(std::shared_ptr<EndpointData_t>{endpoint_data}) 	 <---- does not work!
{
	// std::cerr << "Router for pointers owns data. Be careful with valid pointer!\n";
	// m_router.data();

};


template <typename Ptr_EndpointData_t, typename Enable> 
int 
Router<Ptr_EndpointData_t, Enable>::AddRoute(
	const typename Routers_t::key_type& url, 
	EndpointData_t* endpoint_data) noexcept(false)
{
	UrlUtils::CheckUrlCorrectnessThrow_V(url);

	size_t back_shift = url.back() == '/' ? 1 : 0;

	m_router.put(ptree::path_type{url.substr(1ul, url.length() - back_shift), '/'},
		std::shared_ptr<EndpointData_t>{endpoint_data});
	
	return 0;
};


template <typename Ptr_EndpointData_t, typename Enable>
template <typename... Args> 
int Router<Ptr_EndpointData_t, Enable>::AddRoute(
	const typename Routers_t::key_type& url, Args&&... args) noexcept(false)
{
	static_assert(std::is_constructible_v<EndpointData_t, Args...>,
		"Data type must be constructible with args pack!");

	UrlUtils::CheckUrlCorrectnessThrow_V(url);

	std::allocator<EndpointData_t> alloc;
	EndpointData_t* temp = std::allocator_traits<decltype(alloc)>::allocate(alloc, 1);
	std::allocator_traits<decltype(alloc)>::construct(alloc, temp, std::forward<Args>(args)...);

	return AddRoute(url, temp);
};

template <typename Ptr_EndpointData_t, typename Enable>	
typename Router<Ptr_EndpointData_t, Enable>::EndpointData_t*
Router<Ptr_EndpointData_t, Enable>::FindRoute(
	const typename Routers_t::key_type& url) noexcept(false)
{
	UrlUtils::CheckUrlCorrectnessThrow_V(url);

	size_t back_shift = url.back() == '/' ? 1 : 0;

	return m_router.get_child(ptree::path_type{url.substr(1ul, url.length() - back_shift), '/'}).data().get();

};

template <typename Ptr_EndpointData_t, typename Enable>	
const typename Router<Ptr_EndpointData_t, Enable>::EndpointData_t* 
Router<Ptr_EndpointData_t, Enable>::FindRoute(
	const typename Routers_t::key_type& url) const noexcept(false)
{
	UrlUtils::CheckUrlCorrectnessThrow_V(url);

	size_t back_shift = url.back() == '/' ? 1 : 0;

	return m_router.get(ptree::path_type{url.substr(1ul, url.length() - back_shift), '/'}).get();

};

template <typename Ptr_EndpointData_t, typename Enable>	
std::pair<std::string, 
	typename Router<Ptr_EndpointData_t, Enable>::EndpointData_t*>
Router<Ptr_EndpointData_t, Enable>::FindNearestRoute(
		const typename Routers_t::key_type& url) noexcept(false)
{
	auto route_pieces = 
		UrlUtils::Split(url);

	UrlUtils::CheckUrlCorrectnessThrow_V(url);

	std::string available_route; available_route.reserve(32);
	Routers_t* subtree = &m_router;

	for (size_t k = 1; k < route_pieces.size(); ++k)
	{
		available_route.push_back('/');

		try
		{
			subtree = 
				&subtree->get_child(ptree::path_type{route_pieces[k].data(), '/'});

			available_route.append(route_pieces[k]);			

		} catch (const pt::ptree_bad_path&)
		{
			break;
		}
	}

	available_route.pop_back(); // remove `/'

	return {available_route, subtree->data().get()}; // RVNO?
};

template <typename Ptr_EndpointData_t, typename Enable>
std::pair<std::string, 
	const typename Router<Ptr_EndpointData_t, Enable>::EndpointData_t*>
Router<Ptr_EndpointData_t, Enable>::FindNearestRoute(
		const typename Routers_t::key_type& url) const noexcept(false)
{
	auto route_pieces = 
		UrlUtils::Split(url);

	UrlUtils::CheckUrlCorrectnessThrow_V(url);

	std::string available_route; available_route.reserve(32);
	Routers_t* subtree = &m_router;

	for (size_t k = 1; k < route_pieces.size(); ++k)
	{
		available_route.push_back('/');

		try
		{
			subtree = 
				&subtree->get_child(ptree::path_type{route_pieces[k].data(), '/'});

			available_route.append(route_pieces[k]);
		} catch (const pt::ptree_bad_path&)
		{
			break;
		}
	}

	available_route.pop_back(); // remove `/'

	return {available_route, subtree->data().get()}; // RNVO ?
};
// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================
// ==============================================================

// template <typename EndpointData_t>
// Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>::Router(
// 	EndpointData_t endpoint_data)
// 	: m_router()
// {
// 	m_router.data().operator=({std::move(endpoint_data)});
// };

// template <typename EndpointData_t>
// int Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>::AddRoute(
// 	const typename Routers_t::key_type& url, EndpointData_t endpoint_data)
// {
	// url can determine either directory or path 

	// auto route_pieces = UrlUtils::Split(url);

	// if (!route_pieces[0].empty())
	// {
	// 	// error
	// 	throw std::runtime_error("Url must be relative ( `/...' )!");
	// }

	// Routers_t* subtree = &m_router;

	// for (size_t k = 1; k < route_pieces.size() - 1; ++k)
	// {
	// 	// get child of property tree
	// 	try {
	// 		// if exceptions was thrown subtree not modified?
	// 		subtree = 
	// 			&subtree->get_child(route_pieces[k].data());

	// 	} catch(const pt::ptree_bad_path&)
	// 	{
	// 		// path not found
	// 		// then should add
	// 		while (k < route_pieces.size() - 1)
	// 		{
	// 			subtree = &subtree->put(route_pieces[k].data(), std::optional<EndpointData_t>{std::nullopt}/*, Translator*/);
	// 			++k;
	// 		}
	// 	}
	// }

	// if resource exists then it changes

// 	UrlUtils::CheckUrlCorrectnessThrow_V(url);

// 	size_t back_shift = url.back() == '/' ? 1 : 0;

// 	m_router.put(ptree::path_type{url.substr(1ul, url.length() - back_shift), '/'},
// 		std::optional<EndpointData_t>{std::move(endpoint_data)});
	
// 	return 0;
// };

/**
 * add directory or specific `file` aka .html */
// template <typename EndpointData_t>
// template <typename... Args> 
// int Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>::AddRoute(
// 	const typename Routers_t::key_type& url, Args&&... args)
// {
// 	// url can determine either directory or path 

// 	static_assert(std::is_constructible_v<EndpointData_t, Args...>,
// 		"Data type must be constructible with args pack!");

// 	return AddRoute(url, {std::forward<Args>(args)...}); // copy elision
// };

// template <typename EndpointData_t
// // 	std::enable_if< 
// // 		std::is_invocable_v<
// // 			EndpointD_comp, std::const_ref<EndpointData_t>::type, std::const_ref<EndpointData_t>::type
// // 		>//, bool
// // 	>//, = true
// >	
// std::optional<EndpointData_t>& Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>::FindRoute(
// 	const typename Routers_t::key_type& url) noexcept(false)
// {
// 	// auto route_pieces = 
// 	// 	UrlUtils::Split(url);

// 	UrlUtils::CheckUrlCorrectnessThrow_V(url);

// 	// Routers_t* subtree = &m_router;
// 	// for (size_t k = 0; k < route_pieces.size(); ++k)
// 	// {
// 	// 	subtree = 
// 	// 		&subtree->get_child(route_pieces[k].data());
// 	// }

// 	size_t back_shift = url.back() == '/' ? 1 : 0;

// 	return m_router.get(ptree::path_type{url.substr(1ul, url.length() - back_shift), '/'});
// };

// template <typename EndpointData_t
// // 	std::enable_if< 
// // 		std::is_invocable_v<
// // 			EndpointD_comp, std::const_ref<EndpointData_t>::type, std::const_ref<EndpointData_t>::type
// // 		>//, bool
// // 	>//, = true
// >	
// const std::optional<EndpointData_t>& Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>::FindRoute(
// 	const typename Routers_t::key_type& url) const noexcept(false)
// {
// 	// auto route_pieces = 
// 	// 	UrlUtils::Split(url);

// 	UrlUtils::CheckUrlCorrectnessThrow_V(url);

// 	// Routers_t* subtree = &m_router;
// 	// for (size_t k = 0; k < route_pieces.size(); ++k)
// 	// {
// 	// 	subtree = 
// 	// 		&subtree->get_child(route_pieces[k].data());
// 	// }

// 	size_t back_shift = url.back() == '/' ? 1 : 0;

// 	return m_router.get(ptree::path_type{url.substr(1ul, url.length() - back_shift), '/'});;
// };


// template <typename EndpointData_t
// // 	std::enable_if< 
// // 		std::is_invocable_v<
// // 			EndpointD_comp, std::const_ref<EndpointData_t>::type, std::const_ref<EndpointData_t>::type
// // 		>//, bool
// // 	>//, = true
// >	
// std::pair<std::string, 
// 	std::optional<EndpointData_t>&>
// Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>::FindNearestRoute(
// 		const typename Routers_t::key_type& url) noexcept(false)
// {
// 	auto route_pieces = 
// 		UrlUtils::Split(url);

// 	UrlUtils::CheckUrlCorrectnessThrow_V(url);

// 	std::string available_route{"/"};
// 	Routers_t* subtree = &m_router;

// 	for (size_t k = 1; k < route_pieces.size(); ++k)
// 	{
// 		try
// 		{
// 			subtree = 
// 				&subtree->get_child(ptree::path_type{route_pieces[k].data(), '/'});

// 			available_route.append(route_pieces[k]);
// 			if (k != route_pieces.size() - 1)
// 			{
// 				available_route.push_back('/');
// 			}

// 		} catch (const pt::ptree_bad_path&)
// 		{
// 			break;
// 		}
// 	}

// 	return {available_route, subtree->data()};
// };


// template <typename EndpointData_t
// // 	std::enable_if< 
// // 		std::is_invocable_v<
// // 			EndpointD_comp, std::const_ref<EndpointData_t>::type, std::const_ref<EndpointData_t>::type
// // 		>//, bool
// // 	>//, = true
// >	
// std::pair<std::string, 
// 	const std::optional<EndpointData_t>&>
// Router<EndpointData_t, typename std::enable_if_t<!std::is_pointer_v<EndpointData_t>>>::FindNearestRoute(
// 		const typename Routers_t::key_type& url) const noexcept(false)
// {
// 	auto route_pieces = 
// 		UrlUtils::Split(url);

// 	UrlUtils::CheckUrlCorrectnessThrow_V(url);

// 	std::string available_route{"/"};
// 	Routers_t* subtree = &m_router;

// 	for (size_t k = 1; k < route_pieces.size(); ++k)
// 	{
// 		try
// 		{
// 			subtree = 
// 				&subtree->get_child(ptree::path_type{route_pieces[k].data(), '/'});

// 			available_route.append(route_pieces[k]);
// 			if (k != route_pieces.size() - 1)
// 			{
// 				available_route.push_back('/');
// 			}

// 		} catch (const pt::ptree_bad_path&)
// 		{
// 			break;
// 		}
// 	}

// 	return {available_route, subtree->data()};
// };
