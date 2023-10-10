/**
 * @name linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-ath11k_dp_rx_process_wbm_err
 * @id cpp/linux/d7333a8ec8ca88b106a2f9729b119cb09c7e41dc/ath11k-dp-rx-process-wbm-err
 * @description linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-ath11k_dp_rx_process_wbm_err CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vab_4058) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="rx_buf_rbm"
		and target_0.getQualifier().(ValueFieldAccess).getTarget().getName()="hal_params"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hw_params"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vab_4058)
}

predicate func_2(Parameter vab_4058, Variable vrx_ring_4063, Variable vnum_buffs_reaped_4071, Variable vi_4073) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("ath11k_dp_rxbufs_replenish")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vab_4058
		and target_2.getArgument(1).(VariableAccess).getTarget()=vi_4073
		and target_2.getArgument(2).(VariableAccess).getTarget()=vrx_ring_4063
		and target_2.getArgument(3).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vnum_buffs_reaped_4071
		and target_2.getArgument(3).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_4073
		and target_2.getArgument(4) instanceof EnumConstantAccess)
}

from Function func, Parameter vab_4058, Variable vrx_ring_4063, Variable vnum_buffs_reaped_4071, Variable vi_4073
where
not func_0(vab_4058)
and vab_4058.getType().hasName("ath11k_base *")
and func_2(vab_4058, vrx_ring_4063, vnum_buffs_reaped_4071, vi_4073)
and vrx_ring_4063.getType().hasName("dp_rxdma_ring *")
and vnum_buffs_reaped_4071.getType().hasName("int[3]")
and vi_4073.getType().hasName("int")
and vab_4058.getParentScope+() = func
and vrx_ring_4063.getParentScope+() = func
and vnum_buffs_reaped_4071.getParentScope+() = func
and vi_4073.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
