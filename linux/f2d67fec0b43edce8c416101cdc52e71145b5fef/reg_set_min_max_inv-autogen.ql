/**
 * @name linux-f2d67fec0b43edce8c416101cdc52e71145b5fef-reg_set_min_max_inv
 * @id cpp/linux/f2d67fec0b43edce8c416101cdc52e71145b5fef/reg_set_min_max_inv
 * @description linux-f2d67fec0b43edce8c416101cdc52e71145b5fef-reg_set_min_max_inv 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vfalse_reg_5824, Parameter vis_jmp32_5825, Parameter vtrue_reg_5823, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vis_jmp32_5825
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__reg_bound_offset32")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfalse_reg_5824
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__reg_bound_offset32")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrue_reg_5823
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vfalse_reg_5824, Parameter vis_jmp32_5825, Parameter vtrue_reg_5823
where
func_0(vfalse_reg_5824, vis_jmp32_5825, vtrue_reg_5823, func)
and vfalse_reg_5824.getType().hasName("bpf_reg_state *")
and vis_jmp32_5825.getType().hasName("bool")
and vtrue_reg_5823.getType().hasName("bpf_reg_state *")
and vfalse_reg_5824.getParentScope+() = func
and vis_jmp32_5825.getParentScope+() = func
and vtrue_reg_5823.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
