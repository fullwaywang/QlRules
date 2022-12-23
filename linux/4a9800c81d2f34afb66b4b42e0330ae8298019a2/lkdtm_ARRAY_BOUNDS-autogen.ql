/**
 * @name linux-4a9800c81d2f34afb66b4b42e0330ae8298019a2-lkdtm_ARRAY_BOUNDS
 * @id cpp/linux/4a9800c81d2f34afb66b4b42e0330ae8298019a2/lkdtm-ARRAY-BOUNDS
 * @description linux-4a9800c81d2f34afb66b4b42e0330ae8298019a2-lkdtm_ARRAY_BOUNDS 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnot_checked_324, Variable vchecked_325, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vnot_checked_324
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vchecked_325
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_2(Variable vnot_checked_324, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnot_checked_324
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_2))
}

predicate func_3(Variable vchecked_325, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchecked_325
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_3))
}

predicate func_6(Variable vnot_checked_324) {
	exists(PointerDereferenceExpr target_6 |
		target_6.getOperand().(VariableAccess).getTarget()=vnot_checked_324)
}

predicate func_7(Variable vnot_checked_324) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="data"
		and target_7.getQualifier().(VariableAccess).getTarget()=vnot_checked_324)
}

predicate func_8(Variable vchecked_325) {
	exists(PointerDereferenceExpr target_8 |
		target_8.getOperand().(VariableAccess).getTarget()=vchecked_325)
}

predicate func_9(Variable vchecked_325) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="data"
		and target_9.getQualifier().(VariableAccess).getTarget()=vchecked_325)
}

from Function func, Variable vnot_checked_324, Variable vchecked_325
where
not func_0(vnot_checked_324, vchecked_325, func)
and not func_2(vnot_checked_324, func)
and not func_3(vchecked_325, func)
and vnot_checked_324.getType().hasName("array_bounds_flex_array *")
and func_6(vnot_checked_324)
and func_7(vnot_checked_324)
and vchecked_325.getType().hasName("array_bounds *")
and func_8(vchecked_325)
and func_9(vchecked_325)
and vnot_checked_324.getParentScope+() = func
and vchecked_325.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
