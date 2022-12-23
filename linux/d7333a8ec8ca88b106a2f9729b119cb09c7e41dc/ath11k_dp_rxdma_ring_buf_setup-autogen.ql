/**
 * @name linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-ath11k_dp_rxdma_ring_buf_setup
 * @id cpp/linux/d7333a8ec8ca88b106a2f9729b119cb09c7e41dc/ath11k-dp-rxdma-ring-buf-setup
 * @description linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-ath11k_dp_rxdma_ring_buf_setup CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter var_490) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="rx_buf_rbm"
		and target_0.getQualifier().(ValueFieldAccess).getTarget().getName()="hal_params"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hw_params"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ab"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=var_490)
}

predicate func_2(Parameter var_490) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="ab"
		and target_2.getQualifier().(VariableAccess).getTarget()=var_490)
}

from Function func, Parameter var_490
where
not func_0(var_490)
and var_490.getType().hasName("ath11k *")
and func_2(var_490)
and var_490.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
