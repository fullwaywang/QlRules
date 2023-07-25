/**
 * @name lua-0bfc572e51d9035a615ef6e9523f736c9ffa8e57-luaB_collectgarbage
 * @id cpp/lua/0bfc572e51d9035a615ef6e9523f736c9ffa8e57/luaB-collectgarbage
 * @description lua-0bfc572e51d9035a615ef6e9523f736c9ffa8e57-lbaselib.c-luaB_collectgarbage CVE-2021-44964
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vk_201, AddExpr target_12) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vk_201
		and target_0.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vres_208, ExprStmt target_13) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vres_208
		and target_2.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_13.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_4(Variable vprevious_215, ExprStmt target_14) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vprevious_215
		and target_4.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_6(Variable vres_220, ExprStmt target_15) {
	exists(IfStmt target_6 |
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vres_220
		and target_6.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_8(Variable vres_236, ExprStmt target_16) {
	exists(IfStmt target_8 |
		target_8.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vres_236
		and target_8.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_16.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_10(Parameter vL_191, ExprStmt target_16, Function func) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(FunctionCall).getTarget().hasName("lua_pushnil")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_191
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_10)
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_12(Variable vk_201, AddExpr target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=vk_201
		and target_12.getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_12.getAnOperand().(DivExpr).getRightOperand().(Literal).getValue()="1024"
}

predicate func_13(Parameter vL_191, Variable vres_208, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("lua_pushboolean")
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_191
		and target_13.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vres_208
}

predicate func_14(Parameter vL_191, Variable vprevious_215, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("lua_pushinteger")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_191
		and target_14.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vprevious_215
}

predicate func_15(Parameter vL_191, Variable vres_220, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("lua_pushboolean")
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_191
		and target_15.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vres_220
}

predicate func_16(Parameter vL_191, Variable vres_236, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("lua_pushinteger")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_191
		and target_16.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vres_236
}

from Function func, Parameter vL_191, Variable vk_201, Variable vres_208, Variable vprevious_215, Variable vres_220, Variable vres_236, AddExpr target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16
where
not func_0(vk_201, target_12)
and not func_2(vres_208, target_13)
and not func_4(vprevious_215, target_14)
and not func_6(vres_220, target_15)
and not func_8(vres_236, target_16)
and not func_10(vL_191, target_16, func)
and func_12(vk_201, target_12)
and func_13(vL_191, vres_208, target_13)
and func_14(vL_191, vprevious_215, target_14)
and func_15(vL_191, vres_220, target_15)
and func_16(vL_191, vres_236, target_16)
and vL_191.getType().hasName("lua_State *")
and vk_201.getType().hasName("int")
and vres_208.getType().hasName("int")
and vprevious_215.getType().hasName("int")
and vres_220.getType().hasName("int")
and vres_236.getType().hasName("int")
and vL_191.getFunction() = func
and vk_201.(LocalVariable).getFunction() = func
and vres_208.(LocalVariable).getFunction() = func
and vprevious_215.(LocalVariable).getFunction() = func
and vres_220.(LocalVariable).getFunction() = func
and vres_236.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
