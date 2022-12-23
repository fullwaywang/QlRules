/**
 * @name linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-ath11k_dp_process_rx_err
 * @id cpp/linux/d7333a8ec8ca88b106a2f9729b119cb09c7e41dc/ath11k-dp-process-rx-err
 * @description linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-ath11k_dp_process_rx_err CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vab_3748) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="rx_buf_rbm"
		and target_0.getQualifier().(ValueFieldAccess).getTarget().getName()="hal_params"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hw_params"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vab_3748)
}

predicate func_4(Parameter vab_3748, Variable vret_3754) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("ath11k_warn")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vab_3748
		and target_4.getArgument(1).(StringLiteral).getValue()="failed to parse error reo desc %d\n"
		and target_4.getArgument(2).(VariableAccess).getTarget()=vret_3754)
}

predicate func_5(Parameter vab_3748, Variable vi_3754, Variable vn_bufs_reaped_3755, Variable vrx_ring_3756) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("ath11k_dp_rxbufs_replenish")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vab_3748
		and target_5.getArgument(1).(VariableAccess).getTarget()=vi_3754
		and target_5.getArgument(2).(VariableAccess).getTarget()=vrx_ring_3756
		and target_5.getArgument(3).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vn_bufs_reaped_3755
		and target_5.getArgument(3).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3754
		and target_5.getArgument(4) instanceof EnumConstantAccess)
}

from Function func, Parameter vab_3748, Variable vret_3754, Variable vi_3754, Variable vn_bufs_reaped_3755, Variable vrx_ring_3756
where
not func_0(vab_3748)
and vab_3748.getType().hasName("ath11k_base *")
and func_4(vab_3748, vret_3754)
and func_5(vab_3748, vi_3754, vn_bufs_reaped_3755, vrx_ring_3756)
and vret_3754.getType().hasName("int")
and vi_3754.getType().hasName("int")
and vn_bufs_reaped_3755.getType().hasName("int[3]")
and vrx_ring_3756.getType().hasName("dp_rxdma_ring *")
and vab_3748.getParentScope+() = func
and vret_3754.getParentScope+() = func
and vi_3754.getParentScope+() = func
and vn_bufs_reaped_3755.getParentScope+() = func
and vrx_ring_3756.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
