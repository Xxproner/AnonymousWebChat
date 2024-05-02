#ifndef PARTICIPANT_MIMIC_HEADER__
#define PARTICIPANT_MIMIC_HEADER__

#include <type_traits>
#include <string>
#include <iostream>

struct Participant
{
// private:
  std::string name_;
  std::string key_word_;
  std::string info_;
public:
  Participant() = default;

  Participant(std::string name, std::string key_word, std::string info) :
    name_(std::move(name)), key_word_(std::move(key_word)), info_(std::move(info)) {  }

  struct Comparer
  {
    bool operator()(const Participant& lhs, const Participant& rhs)
    {
      return lhs.name_.compare(rhs.name_) < 0 ? true : false;
    }
  };

  Participant(const Participant& that) :
    name_(that.name_), key_word_(that.key_word_), info_(that.info_) {  }

  const Participant& operator=(const Participant& that)
  {
    name_ = that.name_;
    key_word_ = that.key_word_;
    info_ = that.info_;
    return *this;
  }

  Participant(Participant&& that) noexcept : 
    name_(std::move(that.name_)), key_word_(std::move(that.key_word_)), info_(std::move(that.info_))
  {  }

  const Participant& operator=(Participant&& that) noexcept
  {
    name_ = std::move(that.name_);
    key_word_ = std::move(that.key_word_);
    info_ = std::move(that.info_);

    return *this;
  }

  friend std::ostream& operator<<(std::ostream&, const Participant&);

  ~Participant() = default;
};


std::ostream& operator<<(std::ostream& out, const Participant& participant)
{
  out << "name='" << participant.name_ << "'&key word='" << 
    participant.key_word_ << "'&info='" << participant.info_ << '\'';
  return out;

}

#endif // PARTICIPANT_MIMIC_HEADER__
