#pragma once

// FunctionRef<R(Args...)> -- a non-owning, never-allocating reference to a
// callable (issue #464, #284 batch C).
//
// std::function stores its target inline only when it is trivially copyable
// and fits libstdc++'s local buffer -- 8 bytes on 32-bit Xtensa. A lambda that
// captures four references (16 B) therefore heap-allocates every time one is
// passed as `const std::function&`, which is how BlfSubscriptions' per-packet
// refresh paid 16 B per active subscription per packet.
//
// This is two pointers: the callable's address and a trampoline. It never
// copies or owns the callable, so it is only valid for the duration of the
// call it is passed into -- exactly the visitor/callback-parameter shape. Do
// NOT store one past that call.

#include <memory>
#include <type_traits>
#include <utility>

template <typename Sig>
class FunctionRef;

template <typename R, typename... Args>
class FunctionRef<R(Args...)>
{
public:
	template <typename F,
		typename = std::enable_if_t<!std::is_same_v<std::decay_t<F>, FunctionRef>>>
	FunctionRef(F&& f) noexcept   // NOLINT(google-explicit-constructor): implicit by design
		: _obj(const_cast<void*>(static_cast<const void*>(std::addressof(f))))
		, _call(&invoke<std::remove_reference_t<F>>)
	{
	}

	R operator()(Args... args) const
	{
		return _call(_obj, std::forward<Args>(args)...);
	}

private:
	template <typename F>
	static R invoke(void* obj, Args... args)
	{
		return (*static_cast<F*>(obj))(std::forward<Args>(args)...);
	}

	void* _obj;
	R (*_call)(void*, Args...);
};
