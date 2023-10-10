/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-ath11k_dp_process_rx
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/ath11k-dp-process-rx
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-ath11k_dp_process_rx CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vab_2642) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="rx_buf_rbm"
		and target_0.getQualifier().(ValueFieldAccess).getTarget().getName()="hal_params"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hw_params"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vab_2642)
}

predicate func_2(Variable vrx_ring_2646, Variable vnum_buffs_reaped_2647, Variable vi_2658, Parameter vab_2642) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("ath11k_dp_rxbufs_replenish")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vab_2642
		and target_2.getArgument(1).(VariableAccess).getTarget()=vi_2658
		and target_2.getArgument(2).(VariableAccess).getTarget()=vrx_ring_2646
		and target_2.getArgument(3).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnum_buffs_reaped_2647
		and target_2.getArgument(3).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_2658
		and target_2.getArgument(4) instanceof EnumConstantAccess)
}

from Function func, Variable vrx_ring_2646, Variable vnum_buffs_reaped_2647, Variable vi_2658, Parameter vab_2642
where
not func_0(vab_2642)
and vab_2642.getType().hasName("ath11k_base *")
and func_2(vrx_ring_2646, vnum_buffs_reaped_2647, vi_2658, vab_2642)
and vrx_ring_2646.getParentScope+() = func
and vnum_buffs_reaped_2647.getParentScope+() = func
and vi_2658.getParentScope+() = func
and vab_2642.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
