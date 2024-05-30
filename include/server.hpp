#ifndef SERVER_HPP_
#define SERVER_HPP_

namespace ServerUtils
{
	MHD_Result CharacterSecure(const char*, size_t);

	template <typename TLiteral>
	struct Timer
	{
	  using clock = std::chrono::system_clock;
	private:
	  std::chrono::time_point<clock> start_;
	  TLiteral duration_;
	public:
	  Timer(TLiteral duration) : 
	    start_(std::chrono::system_clock::now()), duration_(duration) { }
	  bool is_time_off() const noexcept
	  {
	    std::chrono::time_point<clock> now = 
	      std::chrono::system_clock::now();
	    return (start_ + duration_) > now;
	  }

	  ~Timer() = default;
	};
} // ServerUtils namespace

class Server
{

public:
	template <typename T>
	typedef MHD_Result MHD_AcceptPolicyCallback(
		  T* cls
		, const sockaddr* addr
		, socklen_t addrlen);

	template <typename T>
	typedef MHD_Result MHD_AccessHandlerCallback (
		  T* cls
		, struct MHD_Connection* connection
		, const char *url
		, const char *method
		, const char *version
		, const char *upload_data
		, size_t *upload_data_size
		, void **con_cls);

	typedef void SelectHandlerCallback(
		 )

	template <typename T1, typename T2>
	Server(
		  uint16_t main_webport
		, &MHD_AccessHandlerCallback<T1> accessCallback_
		, T1* t1 = nullptr
		, &MHD_AcceptPolicyCallback<T2> acceptCallback = nullptr
		, T2* t2 = nullptr
		, &SelectHandlerCallback selectCallback = nullptr) 
	
		: main_webport(main_webport)
		, accessCallback(accessCallback_)
		, accessCallback_add_param(t1)
		, acceptCallback(acceptCallback_)
		, accpetCallback_add_param(t2)

	void start() noexcept(false);

	~Server() noexcept;

private:
	void AddSessionCookie(
		, struct Session* session
		, MHD_Response* response);

	MHD_Result SendPage(
   		  struct MHD_Connection *connection
		, struct Session* session
		, const char* page
		, enum MHD_ResponseMemoryMode MemoryMODE = MHD_RESPMEM_PERSISTENT);

	template <typename T>
	void RequestCompleted (
          T* cls
        , struct MHD_Connection *connection
        , void **con_cls
        , enum MHD_RequestTerminationCode toe);


	struct Session* GetSession (
		, struct MHD_Connection *connection);
private:
	enum {GET, POST};
	
	const size_t POSTBUFFERSIZE; // = 512;
	const size_t MAXNAMESIZE; // = 30;
	const size_t MAXANSWERSIZE; //  = 512;
	const size_t MAXACTIVEMEMBERS; // = 5;

	uint16_t main_webport;
	bool debug;

	typedef DaemonPackage std::tuple<MHD_Daemon*, uint16_t, bool>;
	
	DaemonPackage main_daemon;

	serverDB partpants_list;

	std::forward_list<struct Session*> sessionsList;


	std::function<&MHD_AccessHandlerCallback> accessCallback;
	std::function<&MHD_AcceptPolicyCallback> acceptCallback;
	std::function<&SelectHandlerCallback> selectCallback;

	// TODO:
	// we need to configure signup_thread
	// about termination main server
	// then we need to communicate two thread properly
	// 1) future
	// 2) atomic bool
	// 3) condition_variable
	

	// std::atomic_bool continue_signup_webserver {true}; 

	struct Session
	{
	  struct Participant chat_member;
	  uint32_t STATUS_CODE;

	  std::chrono::time_point<std::chrono::system_clock> start_;
	  unsigned int rc;

	  char sid[33];
	  bool verificate;
	  Session() = default;
	  ~Session() = default;
	};

	struct connection_info_struct
	{
	  struct Session* session;
	  struct MHD_PostProcessor *postprocessor; 
	  uint8_t connectiontype;

	  connection_info_struct() = default;
	  ~connection_info_struct() = default;

	};
	
}

#endif // SERVER_HPP_