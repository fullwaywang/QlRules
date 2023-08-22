/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-quicklistPushHead
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/quicklistPushHead
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-src/quicklist.c-quicklistPushHead CVE-2021-32627
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsz_488, NotExpr target_1, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsz_488
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getThen() instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("_serverAssert")
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="sz < UINT32_MAX"
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("_exit")
		and target_0.getExpr().(ConditionalExpr).getElse().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0)
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsz_488, NotExpr target_1) {
		target_1.getOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_quicklistNodeAllowInsert")
		and target_1.getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="head"
		and target_1.getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("quicklist *")
		and target_1.getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="fill"
		and target_1.getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("quicklist *")
		and target_1.getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsz_488
}

from Function func, Parameter vsz_488, NotExpr target_1
where
not func_0(vsz_488, target_1, func)
and func_1(vsz_488, target_1)
and vsz_488.getType().hasName("size_t")
and vsz_488.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
