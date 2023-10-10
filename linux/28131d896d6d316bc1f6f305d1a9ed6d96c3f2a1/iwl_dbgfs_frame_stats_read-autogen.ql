/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_dbgfs_frame_stats_read
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-dbgfs-frame-stats-read
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_dbgfs_frame_stats_read CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vstats_938, Variable vpos_940, Variable vendpos_940, Variable vidx_941) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("rs_pretty_print_rate")
		and not target_0.getTarget().hasName("rs_pretty_print_rate_v1")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vpos_940
		and target_0.getArgument(1).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vendpos_940
		and target_0.getArgument(1).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vpos_940
		and target_0.getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="last_rates"
		and target_0.getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstats_938
		and target_0.getArgument(2).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vidx_941)
}

from Function func, Parameter vstats_938, Variable vpos_940, Variable vendpos_940, Variable vidx_941
where
func_0(vstats_938, vpos_940, vendpos_940, vidx_941)
and vstats_938.getType().hasName("iwl_mvm_frame_stats *")
and vpos_940.getType().hasName("char *")
and vendpos_940.getType().hasName("char *")
and vidx_941.getType().hasName("int")
and vstats_938.getParentScope+() = func
and vpos_940.getParentScope+() = func
and vendpos_940.getParentScope+() = func
and vidx_941.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
