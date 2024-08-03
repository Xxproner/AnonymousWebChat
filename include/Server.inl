template <typename... Args>
Server::Server(
		  MHD_FLAG exec_flags
		, uint16_t port
		, MHD_AcceptPolicyCallback accessCallback
		, void* param1
		, Args... args)
	: m_router(new Resource("localhost"))
{
	exec_flags = static_cast<MHD_FLAG>(
		static_cast<int>(exec_flags) | MHD_USE_INTERNAL_POLLING_THREAD);

	SaveConfiguration(exec_flags, port, accessCallback, param1, 
		&ReplyToConnection, reinterpret_cast<void*>(this), 
		args..., 
		MHD_OPTION_NOTIFY_COMPLETED, &CompletedConnectionCallback, nullptr,
		MHD_OPTION_END);
}

template <typename... Args>
void Server::SaveConfiguration(Args... args)
{
	ConfigurationCallback = [this, args...]()
	{
		this->server_core.easy_start(args...);
		return MHD_YES;
	};
}

template<typename ...Args, 
	typename std::enable_if<std::is_same<Args, std::add_pointer_t<Server::Resource>>::value>::type...>
int Server::RegisterResources(Resource* res, Args&&... ress)
{
	int return_code = RegisterResource(res);
	return_code |= RegisterResources(ress...);
	return return_code;
}


template <typename AuthT, typename... Args>
void Server::AddAuth(Args&&... args) 
{
	if constexpr(std::is_same_v<AuthT, BasicAuth_t>)
	{
		Auth = std::bind(BasicAuth, std::placeholders::_1, std::forward<Args>(args)...);
	} else if (std::is_same_v<AuthT, DigestAuth_t>)
	{
		Auth = std::bind(DigestAuth, std::placeholders::_1, std::forward<Args>(args)...);
	} else if (std::is_same_v<AuthT, JWT_t>)
	{
		Auth = std::bind(JWTAuth, std::placeholders::_1, std::forward<Args>(args)...);
	} else 
	{
		// static_assert(false, "Not available auth type!");
	}
}

