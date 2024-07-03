#ifndef PARTICIPANT_MIMIC_HEADER__
#define PARTICIPANT_MIMIC_HEADER__

#include <string>

struct Participant
{
// private:
  std::string name;
  std::string password;
  std::string info;
public:
  Participant() = default;

  Participant(std::string _name, std::string _key_word, std::string _info);

  struct Comparer
  {
    bool operator()(const Participant& lhs, const Participant& rhs)
    {
      return lhs.name.compare(rhs.name) < 0 ? true : false;
    }
  };

  bool is_incompleted() const
  {
    return name.empty() && password.empty();
  }

  Participant(const Participant& that);

  Participant& operator=(const Participant& that);

  Participant(Participant&& that) noexcept;

  Participant& operator=(Participant&& that) noexcept;

  
  friend std::ostream& operator<<(std::ostream&, const Participant&);

  ~Participant() = default;
};


std::ostream& operator<<(std::ostream& out, const Participant& participant);

#endif // PARTICIPANT_MIMIC_HEADER__
