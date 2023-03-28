/**
 * @name redis-15ae4e29e537e7ec37f0df1825d9fb2beea67124-xautoclaimCommand
 * @id cpp/redis/15ae4e29e537e7ec37f0df1825d9fb2beea67124/xautoclaimCommand
 * @description redis-15ae4e29e537e7ec37f0df1825d9fb2beea67124-xautoclaimCommand CVE-2022-31144
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcount_3336, LogicalAndExpr target_2, ExprStmt target_1) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vcount_3336
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcount_3336, ExprStmt target_1) {
		target_1.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vcount_3336
}

predicate func_2(Variable vcount_3336, LogicalAndExpr target_2) {
		target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("long long")
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vcount_3336
		and target_2.getAnOperand().(FunctionCall).getTarget().hasName("raxNext")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("raxIterator")
}

from Function func, Variable vcount_3336, ExprStmt target_1, LogicalAndExpr target_2
where
not func_0(vcount_3336, target_2, target_1)
and func_1(vcount_3336, target_1)
and func_2(vcount_3336, target_2)
and vcount_3336.getType().hasName("long")
and vcount_3336.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
