/**
 * @name sqlite3-7694e06461203a466865fc8ed3068e0990a7ca50-unixTempFileDir
 * @id cpp/sqlite3/7694e06461203a466865fc8ed3068e0990a7ca50/unixTempFileDir
 * @description sqlite3-7694e06461203a466865fc8ed3068e0990a7ca50-src/os_unix.c-unixTempFileDir CVE-2016-6153
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, OctalLiteral target_0) {
		target_0.getValue()="7"
		and not target_0.getValue()="3"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_1))
}

predicate func_2(Variable vzDir_5415, Function func, ReturnStmt target_2) {
		target_2.getExpr().(VariableAccess).getTarget()=vzDir_5415
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

from Function func, Variable vzDir_5415, OctalLiteral target_0, ReturnStmt target_2
where
func_0(func, target_0)
and not func_1(func)
and func_2(vzDir_5415, func, target_2)
and vzDir_5415.getType().hasName("const char *")
and vzDir_5415.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
