/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-ath11k_dp_process_rxdma_err
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/ath11k-dp-process-rxdma-err
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-ath11k_dp_process_rxdma_err CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vab_4176) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="rx_buf_rbm"
		and target_0.getQualifier().(ValueFieldAccess).getTarget().getName()="hal_params"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hw_params"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vab_4176)
}

predicate func_2(Parameter vmac_id_4176, Parameter vab_4176, Variable vrx_ring_4180, Variable vnum_buf_freed_4190) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("ath11k_dp_rxbufs_replenish")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vab_4176
		and target_2.getArgument(1).(VariableAccess).getTarget()=vmac_id_4176
		and target_2.getArgument(2).(VariableAccess).getTarget()=vrx_ring_4180
		and target_2.getArgument(3).(VariableAccess).getTarget()=vnum_buf_freed_4190
		and target_2.getArgument(4) instanceof EnumConstantAccess)
}

from Function func, Parameter vmac_id_4176, Parameter vab_4176, Variable vrx_ring_4180, Variable vnum_buf_freed_4190
where
not func_0(vab_4176)
and vab_4176.getType().hasName("ath11k_base *")
and func_2(vmac_id_4176, vab_4176, vrx_ring_4180, vnum_buf_freed_4190)
and vrx_ring_4180.getType().hasName("dp_rxdma_ring *")
and vnum_buf_freed_4190.getType().hasName("int")
and vmac_id_4176.getParentScope+() = func
and vab_4176.getParentScope+() = func
and vrx_ring_4180.getParentScope+() = func
and vnum_buf_freed_4190.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
