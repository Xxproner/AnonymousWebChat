#ifndef SESSION_LIST_HPP
#define SESSION_LIST_HPP

#include <stdlib.h>

#include <chrono>
#include <forward_list>
#include <memory>

#include "Participant.hpp"

struct Session
{
	Session();

	struct Participant member;
	uint32_t status_code;
	bool verificate;
	char sid[33];

	std::chrono::time_point<std::chrono::steady_clock> start;

	~Session() = default;
};

struct SessionsList
{
	Session* FindSession (const char* finding_sid);
	void AddSession(Session* session);
	void ExpireSession() noexcept;
private:
	std::chrono::hours expired_time;
	std::forward_list<std::unique_ptr<Session>> session_list;
};

#endif // SESSION_LIST_HPP