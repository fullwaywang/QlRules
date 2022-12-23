/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_get_tx_rate
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-get-tx-rate
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_get_tx_rate CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_2)
}

predicate func_3(Parameter vmvm_264) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="fw"
		and target_3.getQualifier().(VariableAccess).getTarget()=vmvm_264)
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("bool")
		and target_4.getExpr().(AssignExpr).getRValue() instanceof LogicalAndExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_4))
}

predicate func_7(Parameter vmvm_264, Variable vrate_flags_270) {
	exists(IfStmt target_7 |
		target_7.getCondition().(VariableAccess).getType().hasName("bool")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vrate_flags_270
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="9"
		and target_7.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("iwl_fw_lookup_cmd_ver")
		and target_7.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="fw"
		and target_7.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_264
		and target_7.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_7.getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="8")
}

predicate func_9(Variable vrate_idx_268, Variable vrate_flags_270) {
	exists(LogicalAndExpr target_9 |
		target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vrate_idx_268
		and target_9.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrate_idx_268
		and target_9.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vrate_flags_270
		and target_9.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue() instanceof BinaryBitwiseOperation)
}

predicate func_10(Parameter vmvm_264) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="nvm_data"
		and target_10.getQualifier().(VariableAccess).getTarget()=vmvm_264)
}

from Function func, Parameter vmvm_264, Variable vrate_idx_268, Variable vrate_flags_270
where
not func_2(func)
and not func_3(vmvm_264)
and not func_4(func)
and not func_7(vmvm_264, vrate_flags_270)
and func_9(vrate_idx_268, vrate_flags_270)
and vmvm_264.getType().hasName("iwl_mvm *")
and func_10(vmvm_264)
and vrate_idx_268.getType().hasName("int")
and vrate_flags_270.getType().hasName("u32")
and vmvm_264.getParentScope+() = func
and vrate_idx_268.getParentScope+() = func
and vrate_flags_270.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
