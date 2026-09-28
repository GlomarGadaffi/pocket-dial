#ifndef RECENT_ID_RING_HPP
#define RECENT_ID_RING_HPP

// Issue #554 (b): a tiny fixed ring of recently dropped anchor participant ids,
// so a late upsert for a leg we already dropped cannot claim a fresh call slot
// and start rx + POST for it. No allocation: fixed char arrays, oldest
// overwritten. Not synchronised; the caller holds its own lock (the anchor
// client's _mutex).
//
// An id that does not fit (>= Len - 1 chars) is not recorded rather than
// truncated, so a truncated prefix can never match a different, live leg.

#include <cstddef>
#include <cstring>
#include <string_view>

template <std::size_t N, std::size_t Len>
class RecentIdRing
{
public:
	void add(std::string_view id)
	{
		if (id.empty() || id.size() >= Len) return;
		std::memcpy(_ids[_next], id.data(), id.size());
		_ids[_next][id.size()] = '\0';
		_next = (_next + 1) % N;
	}

	bool contains(std::string_view id) const
	{
		if (id.empty() || id.size() >= Len) return false;
		for (std::size_t i = 0; i < N; ++i)
		{
			if (std::strlen(_ids[i]) == id.size() && std::memcmp(_ids[i], id.data(), id.size()) == 0)
				return true;
		}
		return false;
	}

private:
	char _ids[N][Len] = {};
	std::size_t _next = 0;
};

#endif // RECENT_ID_RING_HPP
