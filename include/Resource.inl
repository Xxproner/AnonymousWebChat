//============================== Resource ========================================

inline bool Server::Resource::operator<(const Resource& that) const noexcept
{
	return strcmp(url, that.url) < 0;
}

inline bool Server::Resource::operator==(const Resource& that) const noexcept
{
	return !(*this < that) && !(that < *this);
}


inline MHD_Result Server::Resource::DoGET( 
	MHD_Connection* conn, const char* uri)
{
	// or bad request
	return Server::SendMethodNotAllowedResponse(conn);
};

// inline MHD_Result Server::Resource::DoHEAD( 
// 	MHD_Connection* conn, const char* uri)
// {
// 	// or bad request
// 	return Server::SendMethodNotAllowedResponse(conn);
// };

inline MHD_Result Server::Resource::DoPOST( 
	MHD_Connection* conn, const char* uri, const char* upload_data, size_t upload_data_size)
{
	// or bad request
	return Server::SendMethodNotAllowedResponse(conn);
};

// inline MHD_Result Server::Resource::DoPUT( 
// 	MHD_Connection* conn, const char* uri, const char* upload_data, size_t upload_data_size)
// {
// 	// or bad request
// 	return Server::SendMethodNotAllowedResponse(conn);
// };

// inline MHD_Result Server::Resource::DoDELETE( 
// 	MHD_Connection* conn, const char* uri, const char* upload_data, size_t upload_data_size)
// {
// 	// or bad request
// 	return Server::SendMethodNotAllowedResponse(conn);
// };

// inline MHD_Result Server::Resource::DoCONNECT( 
// 	MHD_Connection* conn, const char* uri, const char* upload_data, size_t upload_data_size)
// {
// 	// or bad request
// 	return Server::SendMethodNotAllowedResponse(conn);
// };

// inline MHD_Result Server::Resource::DoOPTIONS( 
// 	MHD_Connection* conn, const char* uri, const char* upload_data, size_t upload_data_size)
// {
// 	// or bad request
// 	return Server::SendMethodNotAllowedResponse(conn);
// };

// inline MHD_Result Server::Resource::DoTRACE( 
// 	MHD_Connection* conn, const char* uri, const char* upload_data, size_t upload_data_size)
// {
// 	// or bad request
// 	return Server::SendMethodNotAllowedResponse(conn);
// };

// inline MHD_Result Server::Resource::DoPATCH( 
// 	MHD_Connection* conn, const char* uri, const char* upload_data, size_t upload_data_size)
// {
// 	// or bad request
// 	return Server::SendMethodNotAllowedResponse(conn);
// };


inline Server::Resource::Resource(const char* _url)
	: url(Helper::strdupxx(_url))
	// , configured(false)
{
	// assert(_url && "Resource has null url!");
	// url = strdupxx(_url);
}

inline Server::Resource::~Resource() noexcept
{
	if (url) delete[] url; 
}

//============================== end Resource =====================================
//============================== end Resource =====================================
//============================== end Resource =====================================


//============================== ResourceComp =====================================
//============================== ResourceComp =====================================
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