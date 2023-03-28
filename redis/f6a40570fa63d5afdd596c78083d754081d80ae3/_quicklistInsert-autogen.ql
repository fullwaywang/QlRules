/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-_quicklistInsert
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/-quicklistInsert
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-_quicklistInsert CVE-2021-32627 CVE-2021-32628
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsz_850, ExprStmt target_1, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsz_850
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getThen() instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("_serverAssert")
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="sz < UINT32_MAX"
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("_exit")
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsz_850, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="zl"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("quicklistNode *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ziplistPush")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("ziplistNew")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("void *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsz_850
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

from Function func, Parameter vsz_850, ExprStmt target_1
where
not func_0(vsz_850, target_1, func)
and func_1(vsz_850, target_1)
and vsz_850.getType().hasName("const size_t")
and vsz_850.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
