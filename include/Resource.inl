//============================== Resource ========================================
inline bool Resource::operator<(const Resource& that) const noexcept
{
	return strcmp(url, that.url) < 0;
}

inline bool Resource::operator==(const Resource& that) const noexcept
{
	return !(*this < that) && !(that < *this);
}

// inline void Resource::setConfigurationPolicy(
// 	std::function<MHD_Result(MHD_Connection*, void**)> conf_callb, 
// 	std::function<void(void**)>                        release_callb)
// {
// 	Configure = std::move(conf_callb);
// 	Release = std::move(release_callb);
// 	configured = true;
// }

// inline MHD_Result Resource::Configure(
// 	MHD_Connection* conn,
// 	void** con_cls)
// {
// 	configured = true;
// 	return MHD_YES;
// }

// inline void Resource::Release(
// 	void** con_cls)
// {
// 	configured = false;
// }
//============================== end Resource =====================================


//============================== ResourceComp =====================================
inline bool ResourceComp::operator()(const std::unique_ptr<Resource>& lhs, 
	const std::unique_ptr<Resource>& rhs) const noexcept
{
	return *lhs.get() < *rhs.get();
};

inline bool ResourceComp::operator()(const std::unique_ptr<Resource>& lhs,
	const std::string& url) const noexcept
{
	return strcmp(lhs.get()->url, url.c_str()) < 0;
}

inline bool ResourceComp::operator()(const std::string& url,
	const std::unique_ptr<Resource>& lhs) const noexcept
{
	return strcmp(url.c_str(), lhs.get()->url) < 0;
}

inline bool ResourceComp::operator()(const Resource& res,
	const std::unique_ptr<Resource>& rhs) const noexcept
{
	return strcmp(res.url, rhs.get()->url) < 0;
}

inline bool ResourceComp::operator()(const std::unique_ptr<Resource>& lhs,
	const Resource& res) const noexcept
{
	return strcmp(lhs.get()->url, res.url) < 0;
}

//============================== end ResourceComp==================================