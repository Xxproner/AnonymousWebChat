#include "Participant.hpp"

#include <type_traits>
#include <string>
#include <iostream>

// =========================================================
Participant::Participant(std::string _name, std::string _password, std::string _info) 
// =========================================================
	: name(std::move(_name))
	, password(std::move(_password))
	, info(std::move(_info)) 
{  }

// =========================================================
Participant::Participant(const Participant& that) 
	: name(that.name)
	, password(that.password)
	, info(that.info)
{  }

// =========================================================
Participant& Participant::operator=(const Participant& that)
// =========================================================
{
	name = that.name;
	password = that.password;
	info = that.info;
	return *this;
}

// =========================================================
Participant::Participant(Participant&& that) noexcept 
// =========================================================
	: name(std::move(that.name))
	, password(std::move(that.password))
	, info(std::move(that.info))
{  }

// =========================================================
Participant& Participant::operator=(Participant&& that) noexcept
// =========================================================
	{
		name = std::move(that.name);
		password = std::move(that.password);
		info = std::move(that.info);

		return *this;
	}

// =========================================================
std::ostream& operator<<(std::ostream& out, const Participant& participant)
// =========================================================
{
	out << "name='" << participant.name << "'&key word='" << 
		participant.password << "'&info='" << participant.info << '\'';
	return out;

}

