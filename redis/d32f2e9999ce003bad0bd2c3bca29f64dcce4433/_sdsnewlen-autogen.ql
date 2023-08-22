/**
 * @name redis-d32f2e9999ce003bad0bd2c3bca29f64dcce4433-_sdsnewlen
 * @id cpp/redis/d32f2e9999ce003bad0bd2c3bca29f64dcce4433/-sdsnewlen
 * @description redis-d32f2e9999ce003bad0bd2c3bca29f64dcce4433-src/sds.c-_sdsnewlen CVE-2021-21309
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinitlen_103, Variable vhdrlen_110, LogicalAndExpr target_1, AddExpr target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vinitlen_103
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vhdrlen_110
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vinitlen_103
		and target_0.getExpr().(ConditionalExpr).getThen() instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("__assert_fail")
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(StringLiteral).getValue()="initlen + hdrlen + 1 > initlen"
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("const char[11]")
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vinitlen_103, LogicalAndExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("char")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vinitlen_103
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Parameter vinitlen_103, Variable vhdrlen_110, AddExpr target_2) {
		target_2.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vhdrlen_110
		and target_2.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vinitlen_103
		and target_2.getAnOperand().(Literal).getValue()="1"
}

from Function func, Parameter vinitlen_103, Variable vhdrlen_110, LogicalAndExpr target_1, AddExpr target_2
where
not func_0(vinitlen_103, vhdrlen_110, target_1, target_2, func)
and func_1(vinitlen_103, target_1)
and func_2(vinitlen_103, vhdrlen_110, target_2)
and vinitlen_103.getType().hasName("size_t")
and vhdrlen_110.getType().hasName("int")
and vinitlen_103.getFunction() = func
and vhdrlen_110.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
