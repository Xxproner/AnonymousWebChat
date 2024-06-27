#ifndef PARTICIPANT_MIMIC_HEADER__
#define PARTICIPANT_MIMIC_HEADER__

#include <string>

struct Participant
{
// private:
  std::string name_;
  std::string key_word_;
  std::string info_;
public:
  Participant() = default;

  Participant(std::string name, std::string key_word, std::string info);

  struct Comparer
  {
    bool operator()(const Participant& lhs, const Participant& rhs)
    {
      return lhs.name_.compare(rhs.name_) < 0 ? true : false;
    }
  };

  Participant(const Participant& that);

  Participant& operator=(const Participant& that);

  Participant(Participant&& that) noexcept;

  Participant& operator=(Participant&& that) noexcept;

  
  friend std::ostream& operator<<(std::ostream&, const Participant&);

  ~Participant() = default;
};


std::ostream& operator<<(std::ostream& out, const Participant& participant);

#endif // PARTICIPANT_MIMIC_HEADER__
