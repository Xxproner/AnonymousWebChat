template <typename... Args>
	Server::Server(
		  MHD_FLAG exec_flags
		, uint16_t port
		, MHD_AcceptPolicyCallback accessCallback
		, void* param1
		, Args... args)
{
	server_core.easy_start(exec_flags, port, accessCallback, param1,
		&ReplyToConnection, reinterpret_cast<void*>(this), 
		MHD_OPTION_NOTIFY_COMPLETED, &CompletedConnectionCallback, reinterpret_cast<void*>(this), 
		args...);

	working = true;
}


template<typename ...Args, 
	typename std::enable_if<std::is_same<Args, std::add_pointer_t<Server::Resource>>::value>::type...>
int Server::RegisterResources(Resource* res, Args... ress)
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

//============================== Resource ========================================
inline bool Server::Resource::operator<(const Resource& that) const noexcept
{
	return strcmp(url, that.url) < 0;
}

inline bool Server::Resource::operator==(const Resource& that) const noexcept
{
	return !(*this < that) && !(that < *this);
}

// inline void Server::Resource::setConfigurationPolicy(
// 	std::function<MHD_Result(MHD_Connection*, void**)> conf_callb, 
// 	std::function<void(void**)>                        release_callb)
// {
// 	Configure = std::move(conf_callb);
// 	Release = std::move(release_callb);
// 	configured = true;
// }

inline MHD_Result Server::Resource::Configure(
	MHD_Connection* conn,
	void** con_cls)
{
	configured = true;
	return MHD_YES;
}

inline void Server::Resource::Release(
	void** con_cls)
{
	configured = false;
}
//============================== end Resource =====================================


//============================== ResourceComp =====================================
inline bool Server::ResourceComp::operator()(const std::unique_ptr<Resource>& lhs, 
	const std::unique_ptr<Resource>& rhs) const noexcept
{
	return *lhs.get() < *rhs.get();
};

inline bool Server::ResourceComp::operator()(const std::unique_ptr<Resource>& lhs,
	const std::string& url) const noexcept
{
	return strcmp(lhs.get()->url, url.c_str()) < 0;
}

inline bool Server::ResourceComp::operator()(const std::string& url,
	const std::unique_ptr<Resource>& lhs) const noexcept
{
	return strcmp(url.c_str(), lhs.get()->url) < 0;
}

inline bool Server::ResourceComp::operator()(const Resource& res,
	const std::unique_ptr<Resource>& rhs) const noexcept
{
	return strcmp(res.url, rhs.get()->url) < 0;
}

inline bool Server::ResourceComp::operator()(const std::unique_ptr<Resource>& lhs,
	const Resource& res) const noexcept
{
	return strcmp(lhs.get()->url, res.url) < 0;
}

//============================== end ResourceComp==================================