/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-ath11k_dp_rx_h_defrag_reo_reinject
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/ath11k-dp-rx-h-defrag-reo-reinject
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-ath11k_dp_rx_h_defrag_reo_reinject CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vab_3364) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="rx_buf_rbm"
		and target_0.getQualifier().(ValueFieldAccess).getTarget().getName()="hal_params"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hw_params"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vab_3364)
}

predicate func_2(Variable vab_3364) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="dev"
		and target_2.getQualifier().(VariableAccess).getTarget()=vab_3364)
}

from Function func, Variable vab_3364
where
not func_0(vab_3364)
and vab_3364.getType().hasName("ath11k_base *")
and func_2(vab_3364)
and vab_3364.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
