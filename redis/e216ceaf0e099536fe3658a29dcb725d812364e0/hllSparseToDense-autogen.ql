/**
 * @name redis-e216ceaf0e099536fe3658a29dcb725d812364e0-hllSparseToDense
 * @id cpp/redis/e216ceaf0e099536fe3658a29dcb725d812364e0/hllSparseToDense
 * @description redis-e216ceaf0e099536fe3658a29dcb725d812364e0-hllSparseToDense CVE-2019-10192
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(RelationalOperation target_4, Function func) {
	exists(BreakStmt target_0 |
		target_0.getParent().(IfStmt).getCondition()=target_4
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(RelationalOperation target_4, Function func) {
	exists(LabelStmt target_1 |
		target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vdense_585, RelationalOperation target_4, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("sdsfree")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdense_585
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_3(RelationalOperation target_4, Function func, ReturnStmt target_3) {
		target_3.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_3.getEnclosingFunction() = func
}

predicate func_4(RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getLesserOperand().(BinaryBitwiseOperation).getValue()="16384"
}

from Function func, Variable vdense_585, ExprStmt target_2, ReturnStmt target_3, RelationalOperation target_4
where
not func_0(target_4, func)
and not func_1(target_4, func)
and func_2(vdense_585, target_4, target_2)
and func_3(target_4, func, target_3)
and func_4(target_4)
and vdense_585.getType().hasName("sds")
and vdense_585.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
