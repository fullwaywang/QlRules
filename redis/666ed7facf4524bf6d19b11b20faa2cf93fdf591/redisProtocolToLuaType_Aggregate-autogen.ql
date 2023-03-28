/**
 * @name redis-666ed7facf4524bf6d19b11b20faa2cf93fdf591-redisProtocolToLuaType_Aggregate
 * @id cpp/redis/666ed7facf4524bf6d19b11b20faa2cf93fdf591/redisProtocolToLuaType-Aggregate
 * @description redis-666ed7facf4524bf6d19b11b20faa2cf93fdf591-redisProtocolToLuaType_Aggregate CVE-2021-32626
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlua_191, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("lua_checkstack")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlua_191
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("_serverPanic")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(2).(StringLiteral).getValue()="lua stack limit reach when parsing redis.call reply"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("_exit")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getAnOperand().(CharLiteral).getValue()="37"
}

predicate func_2(Parameter vlua_191, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("char *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("redisProtocolToLuaType")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlua_191
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("char *")
}

predicate func_3(Parameter vlua_191, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("lua_pushboolean")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlua_191
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
}

from Function func, Parameter vlua_191, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vlua_191, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vlua_191, target_2)
and func_3(vlua_191, target_3)
and vlua_191.getType().hasName("lua_State *")
and vlua_191.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
