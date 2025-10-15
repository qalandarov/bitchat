import Testing
import Foundation
@testable import bitchat

/// Tests for ``RateLimiterService``.
///
/// These tests verify that the rate limiter correctly normalizes content, enforces
/// per‑sender and per‑content token bucket limits, and detects recent duplicates
/// using its internal LRU cache. Each test is self‑contained and uses small
/// capacities to exercise edge conditions without long delays.
struct RateLimiterServiceTests {
    /// Normalization should ignore case differences and strip URL query/fragment.
    @Test
    func normalizedContentKeyCaseAndURLStripping() {
        let rl = RateLimiterService()
        let k1 = rl.normalizedContentKey("Hello World")
        let k2 = rl.normalizedContentKey("hello world")
        // Case differences should not affect the key
        #expect(k1 == k2)

        // Query and fragment parts of URLs are stripped before hashing
        let u1 = rl.normalizedContentKey("https://example.com/path?foo=bar")
        let u2 = rl.normalizedContentKey("https://example.com/path#baz")
        #expect(u1 == u2)
    }

    /// Token buckets should allow a fixed number of messages before denying further calls.
    @Test
    func tokenBucketsEnforceLimits() {
        // Set up buckets with capacity 3 each and no refill
        let rl = RateLimiterService(
            senderBucketCapacity: 3,
            senderBucketRefill: 0.0,
            contentBucketCapacity: 3,
            contentBucketRefill: 0.0,
            contentLRUCap: 10
        )
        let senderKey = "sender"
        let contentKey = rl.normalizedContentKey("Test message")
        // First three calls succeed
        #expect(rl.allow(senderKey: senderKey, contentKey: contentKey))
        #expect(rl.allow(senderKey: senderKey, contentKey: contentKey))
        #expect(rl.allow(senderKey: senderKey, contentKey: contentKey))
        // Fourth call should fail due to buckets being exhausted
        #expect(!rl.allow(senderKey: senderKey, contentKey: contentKey))
    }

    /// Recent duplicate detection should respect the time window and LRU cap.
    @Test
    func recentDuplicateDetectionAndLRUEviction() {
        let rl = RateLimiterService(
            senderBucketCapacity: 1,
            senderBucketRefill: 1.0,
            contentBucketCapacity: 1,
            contentBucketRefill: 1.0,
            contentLRUCap: 2
        )
        let key1 = rl.normalizedContentKey("Test1")
        let now = Date()
        rl.recordContentKey(key1, timestamp: now)
        // Within 1 second window this should be considered a duplicate
        let isDup = rl.isRecentDuplicate(contentKey: key1, timestamp: now.addingTimeInterval(0.5), within: 1.0)
        #expect(isDup)
        // Outside the window duplicates should not be detected
        let notDup = rl.isRecentDuplicate(contentKey: key1, timestamp: now.addingTimeInterval(1.5), within: 1.0)
        #expect(!notDup)
        // Record two more keys to force eviction of the first key (cap = 2)
        let key2 = rl.normalizedContentKey("Test2")
        let key3 = rl.normalizedContentKey("Test3")
        rl.recordContentKey(key2, timestamp: now)
        rl.recordContentKey(key3, timestamp: now)
        // key1 should have been evicted and thus not appear as duplicate
        let evictedDup = rl.isRecentDuplicate(contentKey: key1, timestamp: now.addingTimeInterval(0.5), within: 1.0)
        #expect(!evictedDup)
    }
}
