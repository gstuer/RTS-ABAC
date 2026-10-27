package com.gstuer.casc.common;

import com.gstuer.casc.common.DecisionResolver.DecisionResolution;
import com.gstuer.casc.common.pattern.AccessRequestPattern;

import java.time.Instant;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Holds the {@link AccessDecision access decisions} that a policy enforcement point (PEP) enforces for the data
 * frames of one direction, and resolves them for the data frames it enforces.
 * <p>
 * The cache keeps one decision per authorization, i.e. per combination of a flow pattern, an action, and a set of
 * next hops, so that the renewed decision of a policy supersedes its predecessor instead of accumulating next to it.
 * Two decisions of an equal flow pattern remain separate as long as they authorize differently, as the conflict
 * between them is resolved per data frame. A PEP cannot distinguish two policies that authorize equally, since their
 * decisions differ in their period of validity only, which is why collapsing them loses no information. The size of
 * the cache is therefore bounded by the policy set rather than by the time the PEP has been running.
 * <p>
 * The resolution of a flow is moreover memoised per access request pattern, as the decisions of a flow change only
 * when a session initialization arrives or when one of them expires. The memoised resolution of a flow corresponds
 * to the composite decision of the conflicting decisions of that flow: it is derived once, it inherits the minimum
 * of their periods of validity, and it is discarded as soon as that period elapses or the decisions change.
 */
public class DecisionCache {
    private static final int MAX_MEMOIZED_RESOLUTIONS = 1024;

    private final ConcurrentMap<AccessDecision.Authorization, AccessDecision> decisions;
    private final ConcurrentMap<AccessRequestPattern, MemoizedResolution> resolutions;
    private final AtomicLong generation;

    /**
     * Constructs a new, empty {@link DecisionCache decision cache}.
     */
    public DecisionCache() {
        this.decisions = new ConcurrentHashMap<>();
        this.resolutions = new ConcurrentHashMap<>();
        this.generation = new AtomicLong();
    }

    /**
     * Adds an access decision to this cache. A decision that authorizes equally to a cached one supersedes it,
     * whereby the later period of validity prevails, so that a session initialization received out of order cannot
     * shorten the validity of a decision. The decisions whose period of validity has elapsed are removed, and the
     * memoised resolutions are discarded, as both of them may be affected by the added decision.
     *
     * @param decision the access decision to be enforced
     */
    public void addDecision(AccessDecision decision) {
        this.decisions.merge(decision.getAuthorization(), decision,
                (current, update) -> current.getValidUntil().isAfter(update.getValidUntil()) ? current : update);
        this.decisions.values().removeIf(cachedDecision -> !cachedDecision.isValid());

        // The generation is incremented after the decisions were changed, so that a resolution memoised by a
        // concurrent reader is either discarded or was derived from the changed decisions.
        this.generation.incrementAndGet();
        this.resolutions.clear();
    }

    /**
     * Resolves the access decisions of this cache into the decision to be enforced for a data frame, as specified by
     * {@link DecisionResolver#getResolution(Collection, AccessRequestPattern, Instant)}. The resolution is memoised
     * for the period for which it holds, which requires the given instants to be non-decreasing across the calls for
     * one flow. That holds for an enforcing PEP, as it resolves the decisions for the point in time of the
     * enforcement.
     *
     * @param requestPattern the access request pattern of the data frame to be enforced
     * @param instant        the point in time of the enforcement
     * @return the resolution to be enforced, or an empty optional if this cache holds no valid access decision whose
     * flow pattern matches the data frame.
     */
    public Optional<DecisionResolution> getResolution(AccessRequestPattern requestPattern, Instant instant) {
        long currentGeneration = this.generation.get();
        MemoizedResolution memoizedResolution = this.resolutions.get(requestPattern);
        if (Objects.nonNull(memoizedResolution) && memoizedResolution.isValidAt(currentGeneration, instant)) {
            return memoizedResolution.resolution();
        }

        Optional<DecisionResolution> resolution = DecisionResolver.getResolution(this.decisions.values(),
                requestPattern, instant);
        this.memoizeResolution(requestPattern, currentGeneration, resolution);
        return resolution;
    }

    /**
     * Gets the number of access decisions held by this cache, i.e. the number of distinct authorizations the PEP
     * enforces for the direction of this cache.
     *
     * @return the number of cached access decisions.
     */
    public int getDecisionCount() {
        return this.decisions.size();
    }

    /**
     * Gets the number of memoised resolutions held by this cache, i.e. the number of flows for which the resolution
     * of the cached access decisions was derived and still holds.
     *
     * @return the number of memoised resolutions.
     */
    public int getResolutionCount() {
        return this.resolutions.size();
    }

    /**
     * Memoises the resolution of a flow. An absent resolution is memoised as well, as it changes only once an access
     * decision is added, which discards the memoised resolutions. The number of memoised resolutions is bounded, so
     * that a PEP enforcing a flow per data frame pattern cannot exhaust its memory.
     *
     * @param requestPattern the access request pattern the resolution was derived for
     * @param generation     the generation of the access decisions the resolution was derived from
     * @param resolution     the resolution to be memoised
     */
    private void memoizeResolution(AccessRequestPattern requestPattern, long generation,
                                   Optional<DecisionResolution> resolution) {
        if (this.resolutions.size() >= MAX_MEMOIZED_RESOLUTIONS) {
            this.resolutions.clear();
        }
        Instant validUntil = resolution.map(DecisionResolution::validUntil).orElse(Instant.MAX);
        this.resolutions.put(requestPattern, new MemoizedResolution(generation, resolution, validUntil));
    }

    /**
     * Represents the memoised resolution of a flow, which holds as long as the access decisions it was derived from
     * are unchanged and none of them has expired.
     *
     * @param generation the generation of the access decisions the resolution was derived from
     * @param resolution the resolution derived for the flow
     * @param validUntil the point in time until the resolution holds
     */
    private record MemoizedResolution(long generation, Optional<DecisionResolution> resolution, Instant validUntil) {
        private boolean isValidAt(long currentGeneration, Instant instant) {
            return this.generation == currentGeneration && instant.isBefore(this.validUntil);
        }
    }
}
