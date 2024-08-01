#include "ServerCore.hpp"


ServerCore::ServerCore()
  : daemon({nullptr, -1, false}) 
{  }

void ServerCore::stop(bool is_quiesce) noexcept
{
  if (is_init())
  {
    MHD_Daemon* working_process = std::get<0>(daemon);
  
    if (is_quiesce)
    {
      MHD_quiesce_daemon(working_process);
    } else 
    {
      MHD_stop_daemon(working_process);
    }
  }
}

// MHD_Result ServerCore::run()
// {  
//   if (!is_init())
//     std::runtime_error("ServerCore::run(): uninitialized process!");
  
//   MHD_Daemon* working_process = std::get<0>(daemon);

//   return MHD_run(working_process);
// }

// MHD_Result ServerCore::GetFdSets(fd_set* rs, fd_set* ws, fd_set* es, MHD_socket* max) const
// {
//   if (!is_init())
//     std::runtime_error("ServerCore::GetFdSets(): uninitialized process!");
  
//   MHD_Daemon* working_process = std::get<0>(daemon);

//   return MHD_get_fdset (working_process, rs, ws, es, max);
// }

// MHD_Result ServerCore::GetTimeout(MHD_UNSIGNED_LONG_LONG* timeout)
// {
//   if (!is_init())
//     std::runtime_error("ServerCore::GetTimeout(): uninitialized process!");

//   MHD_Daemon* working_process = std::get<0>(daemon);

//   return MHD_get_timeout(working_process, timeout);
// }

ServerCore::~ServerCore() noexcept
{
  this->stop();
}