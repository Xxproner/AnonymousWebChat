#ifndef SERVER_CORE_HPP_
#define SERVER_CORE_HPP_

#include <stddef.h>

#include "microhttpd.h"

#include <tuple>
#include <stdexcept>

class ServerCore
{
public:

	typedef MHD_Result (MHD_AcceptPolicyCallback)(
		  void* cls
		, const sockaddr* addr
		, socklen_t addrlen);

	typedef MHD_Result (MHD_AccessHandlerCallback )(
		  void* cls
		, struct MHD_Connection* connection
		, const char *url
		, const char *method
		, const char *version
		, const char *upload_data
		, size_t *upload_data_size
		, void **con_cls);

	typedef void (MHD_RequestCompletedCallback)(
		  void *cls
		, struct MHD_Connectionconnection
		, void **con_cls
		, enum MHD_RequestTerminationCode toe);

	ServerCore();

	// default start
	template <typename... Args>
	void easy_start(
		  MHD_FLAG
		, uint16_t
		, MHD_AcceptPolicyCallback* acceptCallback
		, void* param1
		, MHD_AccessHandlerCallback* accessCallback
		, void* param2
		, Args... args) noexcept(false);

	void stop() noexcept(false);

	MHD_Result run() noexcept(false);

	MHD_Result GetFdSets(fd_set* rs, fd_set* ws, fd_set* es, MHD_socket* max) const;

	MHD_Result GetTimeout(MHD_UNSIGNED_LONG_LONG* timeout);

	~ServerCore() noexcept;

private:
	
	template <typename T>
	void RequestCompleted (
          T* cls
        , struct MHD_Connection *connection
        , void **con_cls
        , enum MHD_RequestTerminationCode toe);

private:
	
	constexpr bool is_init() const
	{ return std::get<DaemonPackage_size>(daemon); };

	
	typedef std::tuple<MHD_Daemon*, uint16_t, bool> DaemonPackage;
	constexpr static size_t DaemonPackage_size = std::tuple_size<DaemonPackage>::value - 1;

	DaemonPackage daemon;

};

template <typename... Args>
	void ServerCore::easy_start(
		  MHD_FLAG exec_flags
		, uint16_t port
		, MHD_AcceptPolicyCallback* acceptCallback
		, void* param1
		, MHD_AccessHandlerCallback* accessCallback
		, void* param2
		, Args... args)
{
	if (std::get<DaemonPackage_size>(daemon))
		throw std::runtime_error("ServerCore::easy_start(): working proccess already launched!");
	else 
	{
		MHD_Daemon*& working_process = std::get<0>(daemon);

		working_process = MHD_start_daemon(exec_flags, port,
										acceptCallback, param1,
										accessCallback, param2, args...);
		if (working_process == NULL)
			throw std::runtime_error("ServerCore::easy_start(): launch working process error!");
		else 
			std::get<DaemonPackage_size>(daemon) = true;	
	}
}

#endif // SERVER_CORE_HPP_