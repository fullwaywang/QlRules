/**
 * @name redis-0bf90d944313919eb8e63d3588bf63a367f020a3-watchdogSignalHandler
 * @id cpp/redis/0bf90d944313919eb8e63d3588bf63a367f020a3/watchdogSignalHandler
 * @description redis-0bf90d944313919eb8e63d3588bf63a367f020a3-src/debug.c-watchdogSignalHandler CVE-2022-3647
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vuc_2073, FunctionCall target_0) {
		target_0.getTarget().hasName("getMcontextEip")
		and not target_0.getTarget().hasName("getAndSetMcontextEip")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vuc_2073
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("logStackTrace")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
}

from Function func, Variable vuc_2073, FunctionCall target_0
where
func_0(vuc_2073, target_0)
and vuc_2073.getType().hasName("ucontext_t *")
and vuc_2073.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
