#pragma once

// Refill<T> -- rebuild a std::vector IN PLACE so that a same-shape refill
// allocates nothing (issue #463, #284 batch B).
//
// The dashboard snapshot used to be rebuilt from empty every tick: a fresh
// vector of tuples of strings per table, the old one freed -- ~2-5 KB of
// internal-DRAM churn every second on an idle board. Refill reuses the
// elements already there instead: next() hands back the existing element for
// the caller to assign into (a string assigned into keeps its capacity), only
// appends when the table grew, and the destructor trims any surplus. So a
// table whose shape did not change since the last refill costs zero
// allocations; one that grew or shrank pays once, when it changes.
//
//   {
//       Refill<std::pair<std::string, std::string>> r(out);
//       for (...) { auto& e = r.next(); e.first.assign(a); e.second.assign(b); }
//   }   // out now holds exactly the elements produced

#include <cstddef>
#include <vector>

template <typename T>
class Refill
{
public:
	explicit Refill(std::vector<T>& v) : _v(v) {}
	Refill(const Refill&) = delete;
	Refill& operator=(const Refill&) = delete;
	~Refill() { if (_n < _v.size()) _v.resize(_n); }

	T& next()
	{
		if (_n == _v.size()) _v.emplace_back();
		return _v[_n++];
	}

private:
	std::vector<T>& _v;
	size_t _n = 0;
};
