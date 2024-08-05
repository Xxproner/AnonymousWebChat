#include "SessionList.hpp"

#include <string.h>

#include <algorithm>
#include <iostream>

// =========================================================
Session::Session()
// =========================================================
	: status_code(0)
	, verificate(false)
{
	sid[0] = 0;
}

// =========================================================
void Session::UpdateActivity() noexcept
// =========================================================
{
	m_cookie_created_time = std::chrono::steady_clock::now();
}

// =========================================================
void Session::CreateSessionCookie(const std::chrono::time_point<std::chrono::steady_clock>& expired_time) noexcept
// =========================================================
{
	// if (expired_time)

	m_cookie_created_time 		= std::chrono::steady_clock::now();
	m_cookie_expired_time 		= expired_time;
	m_cookie_expired_duration 	= m_cookie_expired_time - m_cookie_created_time;

	if (m_cookie_expired_duration < 0)
	{
		std::cerr << "Expired cookie dutaion is negative!\n";
	}

	snprintf(sid, 33, 
		"%X%X%X%X", rand(), rand(), rand(), rand());
}

// =========================================================
template <typename Rep>
void Session::CreateSessionCookie(const std::chrono::duration<Rep>& expired_duration) noexcept
// =========================================================
{
	m_cookie_created_time 		= std::chrono::steady_clock::now();
	m_cookie_expired_duration 	= expired_duration;
	m_cookie_expired_time 		= m_cookie_created_time + m_cookie_expired_duration;

	if (m_cookie_expired_time < m_cookie_created_time)
	{
		std::cerr << "Expired cookie dutaion is negative!\n";
	}

	snprintf(sid, 33, 
		"%X%X%X%X", rand(), rand(), rand(), rand());
}

// =========================================================
std::string Session::ExpiredTimeToHTTPDate() const noexcept
// =========================================================
{
	// c++17 solution or via api
	std::time_t expired_time = 
		std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + m_cookie_expired_duration);

	std::tm* expired_time_repres = localtime(&expired_time);	
	std::string http_date; http_date.resize(32);

	// Date: <day-name>, <day> <month> <year> <hour>:<minute>:<second> GMT
	strftime(http_date.data(), 32, "GET DAY OF WEEK VIA  %d %m %Y %H:%M:%S GMT", expired_time_repres);

}

// =========================================================
Session* SessionsList::FindSession(const char* finding_sid, size_t sid_len)
// =========================================================
{
	auto iter = std::find_if(session_list.begin(), session_list.end(),
		[finding_sid](std::unique_ptr<Session>& session){
			return strncmp(session.get()->sid, finding_sid, sid_len) == 0;
		});
	return (iter != session_list.end()) ? (*iter).get() : nullptr;
}


// =========================================================
const Session* SessionsList::FindSession(const char* finding_sid, size_t sid_len) const
// =========================================================
{
	auto iter = std::find_if(session_list.begin(), session_list.end(),
		[finding_sid](std::unique_ptr<Session>& session){
			return strncmp(session.get()->sid, finding_sid, sid_len) == 0;
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
		if (now - (*curr)->cookie_created_time() > (*curr)->cookie_expired_time())
		{
			curr = session_list.erase_after(prev);
		} else 
		{
			++curr;
			++prev;
		}
	}
}
