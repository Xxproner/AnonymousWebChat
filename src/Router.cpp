#include "Router.hpp"

class UrlUtils
{
public:
	Split(const std::string&)
	{

	}
}

Router::Router(const Routers_t::key_type& domain)
	: m_router()
{

}

Resource* Router::AddRoute(const Routers_t::key_type& url)
{
	std::vector<std::string_view> routes_pieces = UrlUtils::Split(url);


};