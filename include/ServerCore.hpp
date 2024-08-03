#ifndef SERVER_CORE_HPP_
#define SERVER_CORE_HPP_

#include <stddef.h>

#include "microhttpd.h"

#include <tuple>
#include <stdexcept>

class ServerCore
{
public:
	ServerCore();

	template <typename... Args>
	void easy_start(
		  MHD_FLAG
		, uint16_t
		, MHD_AcceptPolicyCallback acceptCallback
		, void* param1
		, MHD_AccessHandlerCallback accessCallback
		, void* param2
		, Args... args) noexcept(false);

	void stop(bool is_quiesce = false) noexcept;

	// MHD_Result run();

	// MHD_Result run() noexcept(false);

	// MHD_Result GetFdSets(fd_set* rs, fd_set* ws, fd_set* es, MHD_socket* max) const;

	// MHD_Result GetTimeout(MHD_UNSIGNED_LONG_LONG* timeout);

	~ServerCore() noexcept;

private: // methods
	
private:
	
	constexpr bool is_init() const;

	typedef std::tuple<MHD_Daemon*, uint16_t, bool> DaemonPackage;
	constexpr static size_t DaemonPackage_size = std::tuple_size<DaemonPackage>::value - 1;

	DaemonPackage daemon;

};

constexpr bool ServerCore::is_init() const { 
	return std::get<DaemonPackage_size>(daemon); 
};

template <typename... Args>
	void ServerCore::easy_start(
		  MHD_FLAG exec_flags
		, uint16_t port
		, MHD_AcceptPolicyCallback acceptCallback
		, void* param1
		, MHD_AccessHandlerCallback accessCallback
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