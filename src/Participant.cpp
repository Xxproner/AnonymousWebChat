#include "Participant.hpp"

#include <type_traits>
#include <string>
#include <iostream>

Participant::Participant(std::string name, std::string key_word, std::string info) :
    name_(std::move(name)), key_word_(std::move(key_word)), info_(std::move(info)) {  }

Participant::Participant(const Participant& that) :
    name_(that.name_), key_word_(that.key_word_), info_(that.info_) {  }

Participant& Participant::operator=(const Participant& that)
  {
    name_ = that.name_;
    key_word_ = that.key_word_;
    info_ = that.info_;
    return *this;
  }

Participant::Participant(Participant&& that) noexcept : 
    name_(std::move(that.name_)), key_word_(std::move(that.key_word_)), info_(std::move(that.info_))
  {  }

Participant& Participant::operator=(Participant&& that) noexcept
  {
    name_ = std::move(that.name_);
    key_word_ = std::move(that.key_word_);
    info_ = std::move(that.info_);

    return *this;
  }

std::ostream& operator<<(std::ostream& out, const Participant& participant)
{
  out << "name='" << participant.name_ << "'&key word='" << 
    participant.key_word_ << "'&info='" << participant.info_ << '\'';
  return out;

}

