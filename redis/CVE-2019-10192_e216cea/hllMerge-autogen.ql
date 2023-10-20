/**
 * @name redis-e216ceaf0e099536fe3658a29dcb725d812364e0-hllMerge
 * @id cpp/redis/e216ceaf0e099536fe3658a29dcb725d812364e0/hllMerge
 * @description redis-e216ceaf0e099536fe3658a29dcb725d812364e0-hllMerge CVE-2019-10192
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(RelationalOperation target_1, Function func) {
	exists(BreakStmt target_0 |
		target_0.getParent().(IfStmt).getCondition()=target_1
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("long")
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getLesserOperand().(BinaryBitwiseOperation).getValue()="16384"
}

from Function func, RelationalOperation target_1
where
not func_0(target_1, func)
and func_1(target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
