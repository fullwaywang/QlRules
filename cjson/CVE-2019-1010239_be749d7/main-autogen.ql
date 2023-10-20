/**
 * @name cjson-be749d7efa7c9021da746e685bd6dec79f9dd99b-main
 * @id cpp/cjson/be749d7efa7c9021da746e685bd6dec79f9dd99b/main
 * @description cjson-be749d7efa7c9021da746e685bd6dec79f9dd99b-tests/misc_tests.c-main CVE-2019-1010239
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("UnityDefaultTestRun")
		and target_0.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("UnityDefaultTestRun")
		and target_1.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_1.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_1))
}

from Function func
where
not func_0(func)
and not func_1(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
