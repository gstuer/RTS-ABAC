package com.gstuer.casc.common.attribute.predicate.tree;

import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.attribute.predicate.PolicyPredicate;
import com.gstuer.casc.common.attribute.predicate.UnavailableAttributeException;
import com.gstuer.casc.common.time.InstantUtility;

import java.time.Instant;
import java.util.Map;

/**
 * Represents a {@link PredicateTree tree of predicates} that uses the logical XOR-operator to evaluate its underlying
 * {@link PolicyPredicate policy predicates}.
 */
public class XorTree extends PredicateTree {
    /**
     * Constructs a new {@link XorTree}.
     *
     * @param leftChild  first child node of the tree
     * @param rightChild second child node of the tree
     */
    public XorTree(PolicyPredicate leftChild, PolicyPredicate rightChild) {
        super(leftChild, rightChild);
    }

    @Override
    public Evaluation evaluate(Map<AttributeIdentifier, PolicyAttribute<?>> attributes) throws UnavailableAttributeException {
        // Evaluate child predicates
        // TODO Only throw unavail. attr. except. if neither left nor right can be evaluated
        Evaluation left = getLeftChild().evaluate(attributes);
        Evaluation right = getRightChild().evaluate(attributes);

        // Derive tree evaluation from children
        // The result of an exclusive disjunction depends on both evaluations, as it flips as soon as either of them
        // changes. The earliest time for re-evaluation therefore defines the end of validity, so that the result is
        // not enforced beyond the period for which an AASP vouches for either of the attribute values it was derived
        // from.
        boolean result = left.isPositive() ^ right.isPositive();
        Instant endOfValidity = InstantUtility.min(left.getEndOfValidity(), right.getEndOfValidity());
        return new Evaluation(result, endOfValidity);
    }
}
