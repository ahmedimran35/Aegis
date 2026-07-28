package rules

import (
	"regexp"
	"sync"
)

const maxRegexCacheSize = 1000

var (
	regexCache      = make(map[string]*regexp.Regexp)
	regexCacheMu    sync.RWMutex
	regexCacheOrder []string
)

func compileRegex(pattern string) (*regexp.Regexp, error) {
	regexCacheMu.RLock()
	if re, ok := regexCache[pattern]; ok {
		regexCacheMu.RUnlock()
		return re, nil
	}
	regexCacheMu.RUnlock()

	// ReDoS gate: reject nested-quantifier and quantified-alternation
	// shapes before they enter the cache (cheap; once per pattern).
	if err := HasReDoSRisk(pattern); err != nil {
		return nil, err
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCacheMu.Lock()
	defer regexCacheMu.Unlock()

	if len(regexCache) >= maxRegexCacheSize {
		evictCount := maxRegexCacheSize / 10
		if evictCount > len(regexCacheOrder) {
			evictCount = len(regexCacheOrder)
		}
		for i := 0; i < evictCount; i++ {
			delete(regexCache, regexCacheOrder[i])
		}
		regexCacheOrder = regexCacheOrder[evictCount:]
	}

	regexCache[pattern] = re
	regexCacheOrder = append(regexCacheOrder, pattern)
	return re, nil
}
