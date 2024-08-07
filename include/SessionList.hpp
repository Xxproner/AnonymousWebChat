#ifndef SESSION_LIST_HPP
#define SESSION_LIST_HPP

#include <stdlib.h>

#include <chrono>
#include <forward_list>
#include <memory>

// #include "Participant.hpp"

struct Participant;

struct Session
{
	Session();
	
	Participant member_info;

	bool verificate;
	
	void CreateSessionCookie(const std::chrono::time_point<std::chrono::steady_clock>& active_until) noexcept;

	// overloading
	template <typename Rep, typename Period>
	void CreateSessionCookie(const std::chrono::duration<Rep, Period>& active_during) noexcept;

	std::string ExpiredTimeToHTTPDate() const noexcept;

	void UpdateActivity() noexcept;

	const char* cookie() const noexcept
	{ return sid; }

	const std::chrono::time_point<std::chrono::steady_clock>&
		cookie_created_time() const noexcept
	{ return m_cookie_created_time; }

	const std::chrono::time_point<std::chrono::steady_clock>&
		cookie_expired_time() const noexcept
	{ return m_cookie_expired_time; }

	const std::chrono::seconds&
		cookie_expired_duration() const noexcept
	{ return m_cookie_expired_duration;	}

	~Session() = default;
private:

	char sid[33];

	std::chrono::time_point<std::chrono::steady_clock> m_cookie_created_time;

	std::chrono::time_point<std::chrono::steady_clock> m_cookie_expired_time;

	std::chrono::seconds m_cookie_expired_duration;
};

struct SessionsList
{
	Session* FindSession (const char* finding_sid, size_t sid_len);

	
	const Session* FindSession (const char* finding_sid, size_t sid_len) const;

	
	void AddSession(Session* session);

	
	void ExpireSession() noexcept; // expire sessions
private:
	
	std::forward_list<std::unique_ptr<Session>> session_list;
};

// =========================================================
template <typename Rep, typename Period>
void Session::CreateSessionCookie(const std::chrono::duration<Rep, Period>& expired_duration) noexcept
// =========================================================
{
	m_cookie_created_time 		= std::chrono::steady_clock::now();
	m_cookie_expired_duration 	= std::chrono::duration_cast<std::chrono::seconds>(expired_duration);
	m_cookie_expired_time 		= m_cookie_created_time + m_cookie_expired_duration;

	if (m_cookie_expired_time < m_cookie_created_time)
	{
		std::cerr << "Expired cookie dutaion is negative!\n";
	}

	snprintf(sid, 33, 
		"%X%X%X%X", rand(), rand(), rand(), rand());
};


#endif // SESSION_LIST_HPP