package com.gstuer.casc.pdp;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.AccessPolicy;
import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.pdp.attribute.AttributeSubscriber;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.attribute.predicate.PolicyPredicate;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class PolicyEvaluator implements Runnable {
    private final static long REFRESH_THRESHOLD = 350;
    private final static long SLEEP_OFFSET = 300;

    private final AccessPolicy policy;
    private final AttributeSubscriber attributeSubscriber;
    private AccessDecision decision;
    private Thread thread;

    public PolicyEvaluator(AccessPolicy policy, AttributeSubscriber attributeSubscriber) {
        this.policy = policy;
        this.decision = policy.evaluate(Map.of());
        this.attributeSubscriber = attributeSubscriber;

        // Subscribe to all required attributes
        PolicyPredicate predicate = policy.getPredicate();
        predicate.getRequiredAttributeIdentifiers().forEach(this.attributeSubscriber::subscribe);
    }

    public AccessPolicy getPolicy() {
        return this.policy;
    }

    public AccessDecision getDecision() {
        return this.decision;
    }

    /**
     * Starts the periodic evaluation of this evaluator in a new thread. If the periodic evaluation is already in
     * progress and the associated thread is still alive, nothing happens.
     */
    public void startPeriodicEvaluation() {
        if (this.thread != null && this.thread.isAlive()) {
            // Updating is already in progress
            return;
        }
        this.thread = new Thread(this);
        this.thread.start();
    }

    /**
     * Stops the periodic evaluation of this evaluator safely, i.e., without interrupting it but by stopping the
     * execution after the next evaluation period.
     */
    public void stopPeriodicEvaluation() {
        // Stop update loop and detach thread from this evaluator.
        this.thread = null;
    }

    @Override
    public void run() {
        while (this.thread != null) {
            long timeLeft = Instant.now().until(decision.getValidUntil(), TimeUnit.MILLISECONDS.toChronoUnit());
            if (timeLeft < REFRESH_THRESHOLD) {
                this.evaluate();
                continue;
            }

            try {
                Thread.sleep(timeLeft - SLEEP_OFFSET);
            } catch (InterruptedException exception) {
                // The thread was stopped by an external signal.
                this.thread = null;
                break;
            }
        }
    }

    /**
     * Evaluates the policy of this evaluator and sets the decision accordingly.
     */
    protected void evaluate() {
        PolicyPredicate predicate = this.policy.getPredicate();
        Map<AttributeIdentifier, PolicyAttribute<?>> attributes = this.attributeSubscriber.get(predicate.getRequiredAttributeIdentifiers());
        this.decision = this.policy.evaluate(attributes);
    }
}
