#include <vector>
#include <string_view>

class UrlUtils {
public:
	static std::vector<std::string_view>
		Split(const std::string& spliting_string);
};

template <typename T>
/*typename const_ref_details_<T>::clear_T&& */
T create_xvalue()
{
	return T(); // default constructible
};

template <typename EndpointData_t>
Router<EndpointData_t>::Router(const EndpointData_t& endpoint_data)
	: m_router(endpoint_data)
{

};

/**
 * add directory or specific `file` aka .html */
template <typename EndpointData_t>
template <typename... Args> 
int Router<EndpointData_t>::AddRoute(const typename Routers_t::key_type& url, Args&&... args)
{
	// url can determine either directory or path 

	static_assert(std::is_constructible_v<EndpointData_t, Args...>,
		"EndpointData_t must be constructible with args pack!");

	auto route_pieces = UrlUtils::Split(url);

	if (route_pieces[0].compare("/") != 0)
	{
		// error
		return -1;
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
				subtree = &subtree->put(route_pieces[k].data(), create_xvalue<EndpointData_t>());
				++k;
			}
		}	
	}

	// if resource exists then it changes
	subtree->put(route_pieces.crbegin()->data(), EndpointData_t(std::forward<Args>(args)...));
	return 0;
};


template <typename EndpointData_t
// 	std::enable_if< 
// 		std::is_invocable_v<
// 			EndpointD_comp, std::const_ref<EndpointData_t>::type, std::const_ref<EndpointData_t>::type
// 		>//, bool
// 	>//, = true
>	
EndpointData_t* Router<EndpointData_t>::FindNearestRoute(
	const typename Routers_t::key_type& url)
{
	auto route_pieces = 
		UrlUtils::Split(url);

	if (route_pieces[0].compare("/") != 0)
	{
		// url error
		return nullptr;
	}

	Routers_t* subtree = &m_router;
	for (size_t k = 0; k < route_pieces.size(); ++k)
	{
		try 
		{
			subtree = 
				&subtree->get_child(route_pieces[k].data());
		} catch (const pt::ptree_bad_path&)
		{

		}
	}

	return &subtree->data();
};
