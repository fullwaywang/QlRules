/**
 * @name postgresql-0abc1a059e27c5a71a1a186c97d9c0af407469cc-ExecRefreshMatView
 * @id cpp/postgresql/0abc1a059e27c5a71a1a186c97d9c0af407469cc/ExecRefreshMatView
 * @description postgresql-0abc1a059e27c5a71a1a186c97d9c0af407469cc-src/backend/commands/matview.c-ExecRefreshMatView CVE-2022-1552
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrelowner_147, Variable vsave_sec_context_155, Function func, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrelowner_147
		and target_0.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(VariableAccess).getTarget()=vsave_sec_context_155
		and target_0.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

from Function func, Variable vrelowner_147, Variable vsave_sec_context_155, ExprStmt target_0
where
func_0(vrelowner_147, vsave_sec_context_155, func, target_0)
and vrelowner_147.getType().hasName("Oid")
and vsave_sec_context_155.getType().hasName("int")
and vrelowner_147.(LocalVariable).getFunction() = func
and vsave_sec_context_155.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
