/**
 * @name redis-15ae4e29e537e7ec37f0df1825d9fb2beea67124-xautoclaimCommand
 * @id cpp/redis/15ae4e29e537e7ec37f0df1825d9fb2beea67124/xautoclaimCommand
 * @description redis-15ae4e29e537e7ec37f0df1825d9fb2beea67124-src/t_stream.c-xautoclaimCommand CVE-2022-31144
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcount_3336, NotExpr target_1, LogicalAndExpr target_2, ExprStmt target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vcount_3336
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(9)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(NotExpr target_1) {
		target_1.getOperand().(FunctionCall).getTarget().hasName("streamEntryExists")
		and target_1.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_1.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("robj *")
		and target_1.getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("streamID")
}

predicate func_2(Variable vcount_3336, LogicalAndExpr target_2) {
		target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("long long")
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vcount_3336
		and target_2.getAnOperand().(FunctionCall).getTarget().hasName("raxNext")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("raxIterator")
}

predicate func_3(Variable vcount_3336, ExprStmt target_3) {
		target_3.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vcount_3336
}

from Function func, Variable vcount_3336, NotExpr target_1, LogicalAndExpr target_2, ExprStmt target_3
where
not func_0(vcount_3336, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vcount_3336, target_2)
and func_3(vcount_3336, target_3)
and vcount_3336.getType().hasName("long")
and vcount_3336.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
