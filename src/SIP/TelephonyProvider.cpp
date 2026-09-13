#include "TelephonyProvider.hpp"

const char* telephonyProviderName(TelephonyProviderType t)
{
	switch (t)
	{
	case TelephonyProviderType::Loopback:  return "LOOPBACK";
	case TelephonyProviderType::Telephony: return "TELEPHONY-API";
	default:                               return "?";
	}
}

bool telephonyProviderImplemented(TelephonyProviderType t)
{
	// TelephonyAnchorClient (ported from drawbridge) is now registered for
	// Telephony in RequestsHandler's constructor, so this is honest again:
	// both enumerators have a real, working implementation behind them.
	return t == TelephonyProviderType::Loopback || t == TelephonyProviderType::Telephony;
}

bool TelephonyProviderRegistry::registerProvider(TelephonyProviderType t, AnchorClient* provider)
{
	const size_t i = static_cast<size_t>(t);
	if (provider == nullptr || i >= kMaxProviders)
	{
		return false;
	}
	if (_providers[i] != nullptr && _providers[i] != provider)
	{
		return false;  // slot taken by a different instance
	}
	_providers[i] = provider;
	return true;
}

AnchorClient* TelephonyProviderRegistry::select(TelephonyProviderType t) const
{
	const size_t i = static_cast<size_t>(t);
	if (i >= kMaxProviders)
	{
		return nullptr;
	}
	return _providers[i];
}
