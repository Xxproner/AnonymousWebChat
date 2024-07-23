class GetResource : public Server::Resource
{
public:
	GetResource(int _method, const char* _url)
		: Resource(_method, _url)
	{};

	virtual MHD_Result operator()(void* cls, struct MHD_Connection* conn,
				const char* upload_data,
				size_t* upload_data_size, void** con_cls) override
	{
		return SendPage(conn, MHD_HTTP_OK, url);
	};

	virtual ~GetResource() noexcept{};
};

class GeneralGetResource : public GetResource
{
public:
	GeneralGetResource(int _method, const char* _url, std::string_view resource_path)
		: GetResource(_method, _url)
	{
		struct stat file_buf;
		int file_desc;
		if( (file_desc = open(resource_path.data(), O_RDONLY)) != -1 &&
			fstat(file_desc, &file_buf) == 0)
		{
			general_response = MHD_create_response_from_fd(file_buf.st_size, file_desc);

			if (general_response == NULL)
			{
				std::cerr << __FUNCTION__ << ":Failed to create response!";
				close(file_desc);
				assert(false);
			}
			
		}	 else 
		{
			std::cerr << __FUNCTION__;
			perror(" error: Internal failed");
			assert(false);
		}
	};

	MHD_Result operator()(void* cls, struct MHD_Connection* conn,
			const char* upload_data,
			size_t* upload_data_size, void** con_cls) override
	{
		return MHD_queue_response(conn, MHD_HTTP_OK, general_response);
	};

	virtual ~GeneralGetResource() noexcept
	{
		if (general_response)
			MHD_destroy_response(general_response);
	}

private:
	MHD_Response* general_response;
};

class PostDataUtils
{
public:

	static bool FilterCharacters(const char* c_str, size_t size)
	{
		while (size != 0)
		{
			--size;
			if (!isalpha(c_str[size]) && !isdigit(c_str[size]) && 
				 c_str[size] != ' ' && c_str[size] != '_')
				return false;
		}

		return true;
	};

	// TODO: friend of my parent is my friend?
	// friend RegistrationPostResource;

	static bool IsParticipantCompleted(const Participant& member, std::string_view url)
	{
		return (url.compare("/sign_in.html") == 0 || url.compare("/sign_up.html") == 0 || url.compare("/") == 0) 
			&& !member.name.empty() && !member.password.empty(); /* && member.info.empty() */

	};
private:

};

// general post resource
// class PostResource : public Server::Resource
// {
// public:
// 	// typedef MHD_Result (PostDataHandler)(MHD_Connection*, Session*);
// 	typedef MHD_Result (PostDataHandler )(MHD_Connection*                     );
// 	typedef MHD_Result (PostDataIterator)(MHD_Connection*, const char*, size_t);

// 	PostResource(const char* _url, 
// 				PostDataIterator _process_post_data,
// 				PostDataHandler  _handle_post_data)
// 		: Resource(HTTP::POST, _url)
// 		, process_post_data(_process_post_data)
// 		, handle_post_data(_handle_post_data)
// 	{};

// 	virtual MHD_Result operator()(void* cls, struct MHD_Connection* connection,
// 				const char* upload_data,
// 				size_t* upload_data_size, void** con_cls) override
// 	{	
// 		if (*upload_data_size > 0)
// 		{
// 			process_post_data(connection, 
// 				upload_data, *upload_data_size);

// 			return MHD_YES;
// 		}

// 		// return handle_post_data(connection, session);
// 		return handle_post_data(connection);
// 	};

// private: // members
// 	std::function<PostDataIterator> process_post_data;
// 	std::function<PostDataHandler > handle_post_data;
// };

// for sign in and sign up
class RegistrationPostResource : public Server::Resource // PostResource
{
private:
	// take for compability definitions first!
	static ServerDB db_server_interface;
	
public:
	RegistrationPostResource(const char* _url)
		: Resource(HTTP::POST, _url)
	{};

	MHD_Result HandlePostData(void* cls, MHD_Connection* connection, void** con_cls)
	{
		if (!PostDataUtils::IsParticipantCompleted(member, url))
		{
			// not completed data
			Server::SendBadRequestResponse(connection);
			return MHD_NO;
		}

		int db_exec_code = 0;
		if (strcmp(url, "/") == 0 || strcmp(url, "/sign_in.html") == 0)
		{
			db_exec_code = db_server_interface.AccessParticipant(member);
		} else // dont need to check url
		{
			db_exec_code = db_server_interface.AddParticipant(member);
		}

		// if we don't call queue_response 
		// then microhttpd craches
		if (db_exec_code != ServerDB::DB_OK)
		{
			http_code_t http_code;
			std::string db_bad_message = db_server_interface.strDBError(db_exec_code, http_code);
			return SendHTMLContent(connection, db_bad_message, http_code);
		}

		SendHTMLContent(connection, "YES!", MHD_HTTP_OK);
		return MHD_YES;

	};

	virtual MHD_Result operator()(void* cls, struct MHD_Connection* connection,
				const char* upload_data,
				size_t* upload_data_size, void** con_cls) override
	{	
		if (*upload_data_size > 0)
		{
			MHD_post_process(reinterpret_cast<MHD_PostProcessor*>(*con_cls), 
				upload_data, *upload_data_size);

			*upload_data_size = 0; // ????

			return MHD_YES;
		}
#warning "Bad responsibility of upload_data!"

		// return handle_post_data(connection, session);
		return HandlePostData(cls, connection, con_cls);
	};

	static MHD_Result PostIterator(void *cls, enum MHD_ValueKind kind, 
					const char *key, const char *filename, 
					const char *content_type, const char *transfer_encoding, 
					const char *data, uint64_t off, size_t size)
	{
		std::ignore = kind;
		std::ignore = filename;
		std::ignore = content_type;
		std::ignore = transfer_encoding;
		std::ignore = off;

		if (size > 0)
		{ // for now it is only @sign in@ option
			if (!PostDataUtils::FilterCharacters(data, size))
			{
				return MHD_NO;
			}

			RegistrationPostResource* res = 
				reinterpret_cast<RegistrationPostResource*>(cls);
			
			Participant& member = res->member;
			
			SWITCH(key)
			{
				CASE("name"):
				{
					member.name.append(data);
					break;
				}
				CASE("password"):
				{
					member.password.append(data);
					break;
				}
				CASE("info"):
				{
					member.info.append(data);
					break;
				}
				DEFAULT:
				{
					return MHD_NO;
				}
			}
		}

		return MHD_YES;
	};

	// configuration for first connection
	// imitation of ctor
	MHD_Result Configure(MHD_Connection* conn, void** con_cls) override
	{
		// clear resources
		member.clear();
		uniq_pp.reset(nullptr);

		// get resources		
		auto temp = CreatePostProcessor(conn);
		if (!temp)
		{
			Server::SendBadRequestResponse(conn);
			return MHD_NO;
		}

		uniq_pp.reset(temp);

		*con_cls = uniq_pp.get();

		return MHD_YES;
	}

	// termination connection
	// imitation of dtor
	void Release(void** con_cls) override
	{
		std::ignore = con_cls;

		uniq_pp.reset(nullptr);
	}

	class PostProcessorDestroyer
	{
	public:
		auto operator()(MHD_PostProcessor* pp) const noexcept
			-> decltype(MHD_destroy_post_processor(pp)) 
		{
			if (pp)
			{
				return MHD_destroy_post_processor(pp);
			}

			return MHD_YES;
		};
	};
private: // methods
	MHD_PostProcessor* CreatePostProcessor(MHD_Connection* conn) // const
	{	
		const char* content_type = MHD_lookup_connection_value(conn, MHD_HEADER_KIND,
			"Content-Type");

		// what associative of || operator --> or <--
		if (!content_type || !AvailableContentType(content_type))
		{
			SendStringContent(conn, 
				"Instance of content-type header not allowed!", MHD_HTTP_BAD_REQUEST);
			return nullptr;
		}

		MHD_PostProcessor* temp_pp = MHD_create_post_processor(
			conn, kPostBufferSize, 
			&RegistrationPostResource::PostIterator, 
			reinterpret_cast<void*>(this));
		if (!temp_pp)
		{
			Server::SendInternalErrResponse(conn);
			return nullptr;
		}

		return temp_pp;
	}


	inline bool AvailableContentType(std::string_view content_type) const 
	{
		// this values are passed by MHD
		return (content_type.compare(MHD_HTTP_POST_ENCODING_FORM_URLENCODED) == 0) ||
			(content_type.compare(MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA) == 0);
	}

private: // members
	static const size_t kPostBufferSize = 512;
	Participant member;
	std::unique_ptr<MHD_PostProcessor, PostProcessorDestroyer> uniq_pp;

	// Session* session;
	// static SessionsList session_list;
};

ServerDB RegistrationPostResource::db_connector.open(DB_PATH); // ??