/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-ziplistMerge
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/ziplistMerge
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-ziplistMerge CVE-2021-326271 CVE-2021-32628
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vzlbytes_894, ExprStmt target_1, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vzlbytes_894
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getThen() instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("_serverAssert")
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="zlbytes < UINT32_MAX"
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("_exit")
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0)
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vzlbytes_894, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("zrealloc")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vzlbytes_894
}

from Function func, Variable vzlbytes_894, ExprStmt target_1
where
not func_0(vzlbytes_894, target_1, func)
and func_1(vzlbytes_894, target_1)
and vzlbytes_894.getType().hasName("size_t")
and vzlbytes_894.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
