#include "SessionList.hpp"

#include <algorithm>

#include <string.h>
// =========================================================
Session::Session()
// =========================================================
	: status_code(0)
	, verificate(false)
	, start(std::chrono::steady_clock::now())
{
	snprintf(sid, 33, 
		"%X%X%X%X", rand(), rand(), rand(), rand());
}

// =========================================================
void Session::UpdateActivity() noexcept
// =========================================================
{
	start = std::chrono::steady_clock::now();
}


// =========================================================
Session* SessionsList::FindSession(const char* finding_sid)
// =========================================================
{
	auto iter = std::find_if(session_list.begin(), session_list.end(),
		[finding_sid](std::unique_ptr<Session>& session){
			return strcmp(session.get()->sid, finding_sid) == 0;
		});
	return (iter != session_list.end()) ? (*iter).get() : nullptr;
}

// =========================================================
void SessionsList::AddSession(Session* session)
// =========================================================
{
	session_list.push_front(std::unique_ptr<Session>(session));
}


// =========================================================
void SessionsList::ExpireSession() noexcept
// =========================================================
{
	// create your own data structure
	std::chrono::time_point<std::chrono::steady_clock> now =
		std::chrono::steady_clock::now();
	auto prev = session_list.cbefore_begin();
	for (auto curr = std::next(prev); curr != session_list.cend(); )
	{
		if (now - (*curr)->start > expired_time)
		{
			curr = session_list.erase_after(prev);
		} else 
		{
			++curr;
			++prev;
		}
	}
}
