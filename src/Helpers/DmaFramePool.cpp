#include "DmaFramePool.hpp"

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "esp_attr.h"
#else
#include <mutex>
#endif

namespace l2rtp
{
namespace
{
	std::atomic<uint32_t> s_exhaustions{0};
	std::atomic<uint32_t> s_allocations{0};

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Pool storage in internal SRAM with DMA attribute.
	static DMA_ATTR FrameBuffer s_frames[DmaFramePool::kPoolSize];
	static QueueHandle_t       s_poolQueue = nullptr;
	static portMUX_TYPE         s_initMux   = portMUX_INITIALIZER_UNLOCKED;

	void poolInitInternal()
	{
		portENTER_CRITICAL(&s_initMux);
		if (s_poolQueue == nullptr)
		{
			s_poolQueue = xQueueCreate(DmaFramePool::kPoolSize, sizeof(FrameBuffer*));
			if (s_poolQueue != nullptr)
			{
				for (size_t i = 0; i < DmaFramePool::kPoolSize; ++i)
				{
					FrameBuffer* p = &s_frames[i];
					(void)xQueueSend(s_poolQueue, &p, 0);
				}
			}
		}
		portEXIT_CRITICAL(&s_initMux);
	}
#else
	static FrameBuffer  s_frames[DmaFramePool::kPoolSize];
	static FrameBuffer* s_freeStack[DmaFramePool::kPoolSize];
	static size_t       s_top = 0;
	static bool         s_initialized = false;
	static std::mutex   s_mutex;

	void poolInitInternalUnlocked()
	{
		for (size_t i = 0; i < DmaFramePool::kPoolSize; ++i)
		{
			s_freeStack[i] = &s_frames[i];
		}
		s_top = DmaFramePool::kPoolSize;
		s_initialized = true;
	}

	void poolInitInternal()
	{
		std::lock_guard<std::mutex> lock(s_mutex);
		if (!s_initialized)
		{
			poolInitInternalUnlocked();
		}
	}
#endif
}   // namespace

void DmaFramePool::init()
{
	poolInitInternal();
}

DmaFramePool::Handle DmaFramePool::acquire()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	if (s_poolQueue == nullptr)
	{
		poolInitInternal();
	}

	FrameBuffer* buf = nullptr;
	if (s_poolQueue != nullptr && xQueueReceive(s_poolQueue, &buf, 0) == pdTRUE)
	{
		s_allocations.fetch_add(1, std::memory_order_relaxed);
		return Handle(buf);
	}
	s_exhaustions.fetch_add(1, std::memory_order_relaxed);
	return Handle(nullptr);
#else
	std::lock_guard<std::mutex> lock(s_mutex);
	if (!s_initialized)
	{
		poolInitInternalUnlocked();
	}

	if (s_top > 0)
	{
		--s_top;
		s_allocations.fetch_add(1, std::memory_order_relaxed);
		return Handle(s_freeStack[s_top]);
	}
	s_exhaustions.fetch_add(1, std::memory_order_relaxed);
	return Handle(nullptr);
#endif
}

void DmaFramePool::Handle::release() noexcept
{
	if (_buf == nullptr)
	{
		return;
	}

	FrameBuffer* bufToReturn = _buf;
	_buf = nullptr;

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	if (s_poolQueue != nullptr)
	{
		(void)xQueueSend(s_poolQueue, &bufToReturn, 0);
	}
#else
	std::lock_guard<std::mutex> lock(s_mutex);
	if (s_top < DmaFramePool::kPoolSize)
	{
		s_freeStack[s_top++] = bufToReturn;
	}
#endif
}

uint32_t DmaFramePool::getExhaustions() noexcept
{
	return s_exhaustions.load(std::memory_order_relaxed);
}

uint32_t DmaFramePool::getAllocations() noexcept
{
	return s_allocations.load(std::memory_order_relaxed);
}

size_t DmaFramePool::available() noexcept
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	if (s_poolQueue == nullptr)
	{
		return 0;
	}
	return static_cast<size_t>(uxQueueMessagesWaiting(s_poolQueue));
#else
	std::lock_guard<std::mutex> lock(s_mutex);
	return s_top;
#endif
}

void DmaFramePool::resetStats() noexcept
{
	s_exhaustions.store(0, std::memory_order_relaxed);
	s_allocations.store(0, std::memory_order_relaxed);
}

}   // namespace l2rtp
