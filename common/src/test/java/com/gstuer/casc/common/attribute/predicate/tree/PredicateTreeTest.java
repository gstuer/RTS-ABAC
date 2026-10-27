package com.gstuer.casc.common.attribute.predicate.tree;

import com.gstuer.casc.common.attribute.predicate.PolicyPredicate;
import com.gstuer.casc.common.attribute.predicate.StaticResultPredicate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the period of validity that a {@link PredicateTree tree of predicates} derives for its result. That period
 * bounds the period of validity of the access decision a PDP derives from the policy, so that a result must not
 * outlive the attribute values it was derived from: beyond them, no AASP vouches for the system state the result
 * describes.
 */
public class PredicateTreeTest {
    private PolicyPredicate shortLivedTruth;
    private PolicyPredicate longLivedTruth;
    private PolicyPredicate shortLivedFalsehood;
    private PolicyPredicate longLivedFalsehood;
    private Instant shortExpiry;

    @BeforeEach
    public void setUp() {
        this.shortLivedTruth = new StaticResultPredicate(true, Duration.ofSeconds(5));
        this.longLivedTruth = new StaticResultPredicate(true, Duration.ofSeconds(600));
        this.shortLivedFalsehood = new StaticResultPredicate(false, Duration.ofSeconds(5));
        this.longLivedFalsehood = new StaticResultPredicate(false, Duration.ofSeconds(600));
        this.shortExpiry = Instant.now().plusSeconds(5);
    }

    /**
     * A conjunction holds only while both of its operands hold, so that its result expires with the first of them.
     */
    @Test
    public void testConjunctionExpiresWithTheFirstOperand() throws Exception {
        PolicyPredicate.Evaluation evaluation = new AndTree(this.longLivedTruth, this.shortLivedTruth)
                .evaluate(Map.of());

        assertTrue(evaluation.isPositive());
        this.assertExpiresWithTheFirstOperand(evaluation);
    }

    /**
     * An exclusive disjunction depends on both of its operands regardless of their results, as the result flips as
     * soon as either of them changes. Its result therefore expires with the first of them, also if the operand that
     * expires first is the negative one.
     */
    @Test
    public void testExclusiveDisjunctionExpiresWithTheFirstOperand() throws Exception {
        PolicyPredicate.Evaluation evaluation = new XorTree(this.longLivedTruth, this.shortLivedFalsehood)
                .evaluate(Map.of());

        assertTrue(evaluation.isPositive(), "A truth and a falsehood yield an exclusive disjunction that holds.");
        this.assertExpiresWithTheFirstOperand(evaluation);
    }

    /**
     * A disjunction of two negative operands expires with the first of them, as it turns positive as soon as either
     * of them changes.
     */
    @Test
    public void testNegativeDisjunctionExpiresWithTheFirstOperand() throws Exception {
        PolicyPredicate.Evaluation evaluation = new OrTree(this.longLivedFalsehood, this.shortLivedFalsehood)
                .evaluate(Map.of());

        assertFalse(evaluation.isPositive());
        this.assertExpiresWithTheFirstOperand(evaluation);
    }

    /**
     * A disjunction that holds because of one operand alone holds as long as that operand does, as its result is
     * independent of the other one. This is the one case in which a result outlives the attribute value that expires
     * first, which is why the period of validity is derived from the evaluation rather than from the set of
     * attributes a policy requires.
     */
    @Test
    public void testPositiveDisjunctionHoldsAsLongAsItsPositiveOperand() throws Exception {
        PolicyPredicate.Evaluation evaluation = new OrTree(this.longLivedTruth, this.shortLivedFalsehood)
                .evaluate(Map.of());

        assertTrue(evaluation.isPositive());
        assertTrue(evaluation.getEndOfValidity().isAfter(this.shortExpiry.plusSeconds(1)),
                "The result holds while its positive operand does.");
    }

    private void assertExpiresWithTheFirstOperand(PolicyPredicate.Evaluation evaluation) {
        assertTrue(evaluation.getEndOfValidity().isBefore(this.shortExpiry.plusSeconds(1)),
                "The result must not outlive the operand that expires first.");
        assertTrue(evaluation.getEndOfValidity().isAfter(this.shortExpiry.minusSeconds(1)));
    }
}
