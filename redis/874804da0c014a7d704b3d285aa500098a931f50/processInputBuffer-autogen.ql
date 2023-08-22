/**
 * @name redis-874804da0c014a7d704b3d285aa500098a931f50-processInputBuffer
 * @id cpp/redis/874804da0c014a7d704b3d285aa500098a931f50/processInputBuffer
 * @description redis-874804da0c014a7d704b3d285aa500098a931f50-src/networking.c-processInputBuffer CVE-2016-10517
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(BitwiseOrExpr target_0 |
		target_0.getValue()="1088"
		and target_0.getParent().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getParent().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("client *")
		and target_0.getParent().(BitwiseAndExpr).getRightOperand() instanceof BinaryBitwiseOperation
		and target_0.getParent().(BitwiseAndExpr).getParent().(IfStmt).getThen() instanceof BreakStmt
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func, BinaryBitwiseOperation target_1) {
		target_1.getValue()="64"
		and target_1.getParent().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getParent().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("client *")
		and target_1.getParent().(BitwiseAndExpr).getParent().(IfStmt).getThen() instanceof BreakStmt
		and target_1.getEnclosingFunction() = func
}

from Function func, BinaryBitwiseOperation target_1
where
not func_0(func)
and func_1(func, target_1)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
