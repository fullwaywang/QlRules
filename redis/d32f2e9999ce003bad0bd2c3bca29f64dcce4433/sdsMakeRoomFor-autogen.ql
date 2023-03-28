/**
 * @name redis-d32f2e9999ce003bad0bd2c3bca29f64dcce4433-sdsMakeRoomFor
 * @id cpp/redis/d32f2e9999ce003bad0bd2c3bca29f64dcce4433/sdsMakeRoomFor
 * @description redis-d32f2e9999ce003bad0bd2c3bca29f64dcce4433-sdsMakeRoomFor CVE-2021-21309
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_235, Variable vnewlen_235, ExprStmt target_2, RelationalOperation target_3, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnewlen_235
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_235
		and target_0.getExpr().(ConditionalExpr).getThen() instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("__assert_fail")
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(StringLiteral).getValue()="newlen > len"
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("const char[15]")
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlen_235, Variable vnewlen_235, Variable vhdrlen_237, AddExpr target_4, ExprStmt target_5, AddExpr target_6, ExprStmt target_7, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vhdrlen_237
		and target_1.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnewlen_235
		and target_1.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_1.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_235
		and target_1.getExpr().(ConditionalExpr).getThen() instanceof Literal
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("__assert_fail")
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(StringLiteral).getValue()="hdrlen + newlen + 1 > len"
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("const char[15]")
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_1)
		and target_1.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_1.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vlen_235, Variable vnewlen_235, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnewlen_235
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_235
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("size_t")
}

predicate func_3(Variable vnewlen_235, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vnewlen_235
		and target_3.getGreaterOperand().(MulExpr).getValue()="1048576"
}

predicate func_4(Variable vlen_235, AddExpr target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vlen_235
		and target_4.getAnOperand().(Literal).getValue()="1"
}

predicate func_5(Variable vnewlen_235, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("char")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sdsReqType")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnewlen_235
}

predicate func_6(Variable vnewlen_235, Variable vhdrlen_237, AddExpr target_6) {
		target_6.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vhdrlen_237
		and target_6.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnewlen_235
		and target_6.getAnOperand().(Literal).getValue()="1"
}

predicate func_7(Variable vhdrlen_237, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhdrlen_237
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sdsHdrSize")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("char")
}

from Function func, Variable vlen_235, Variable vnewlen_235, Variable vhdrlen_237, ExprStmt target_2, RelationalOperation target_3, AddExpr target_4, ExprStmt target_5, AddExpr target_6, ExprStmt target_7
where
not func_0(vlen_235, vnewlen_235, target_2, target_3, func)
and not func_1(vlen_235, vnewlen_235, vhdrlen_237, target_4, target_5, target_6, target_7, func)
and func_2(vlen_235, vnewlen_235, target_2)
and func_3(vnewlen_235, target_3)
and func_4(vlen_235, target_4)
and func_5(vnewlen_235, target_5)
and func_6(vnewlen_235, vhdrlen_237, target_6)
and func_7(vhdrlen_237, target_7)
and vlen_235.getType().hasName("size_t")
and vnewlen_235.getType().hasName("size_t")
and vhdrlen_237.getType().hasName("int")
and vlen_235.getParentScope+() = func
and vnewlen_235.getParentScope+() = func
and vhdrlen_237.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
