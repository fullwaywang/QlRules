/**
 * @name redis-666ed7facf4524bf6d19b11b20faa2cf93fdf591-luaReplyToRedisReply
 * @id cpp/redis/666ed7facf4524bf6d19b11b20faa2cf93fdf591/luaReplyToRedisReply
 * @description redis-666ed7facf4524bf6d19b11b20faa2cf93fdf591-luaReplyToRedisReply CVE-2021-32626
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vc_341, Parameter vlua_341, ExprStmt target_5, FunctionCall target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("lua_checkstack")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlua_341
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyErrorFormat")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_341
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="reached lua stack limit"
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(0)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(0).getFollowingStmt()=target_0)
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vlua_341, ExprStmt target_7, ExprStmt target_3, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("lua_settop")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlua_341
		and target_1.getExpr().(FunctionCall).getArgument(1).(SubExpr).getValue()="-2"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_1)
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vlua_341, Function func, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("lua_settop")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlua_341
		and target_3.getExpr().(FunctionCall).getArgument(1).(SubExpr).getValue()="-2"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Function func, ReturnStmt target_4) {
		target_4.toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Parameter vc_341, Parameter vlua_341, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("addReplyBulkCBuffer")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_341
		and target_5.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("lua_tolstring")
		and target_5.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlua_341
		and target_5.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_5.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_5.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("lua_objlen")
		and target_5.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlua_341
		and target_5.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
}

predicate func_6(Parameter vlua_341, FunctionCall target_6) {
		target_6.getTarget().hasName("lua_type")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vlua_341
		and target_6.getArgument(1).(UnaryMinusExpr).getValue()="-1"
}

predicate func_7(Parameter vc_341, Parameter vlua_341, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("luaReplyToRedisReply")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_341
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlua_341
}

from Function func, Parameter vc_341, Parameter vlua_341, ExprStmt target_3, ReturnStmt target_4, ExprStmt target_5, FunctionCall target_6, ExprStmt target_7
where
not func_0(vc_341, vlua_341, target_5, target_6, func)
and not func_1(vlua_341, target_7, target_3, func)
and func_3(vlua_341, func, target_3)
and func_4(func, target_4)
and func_5(vc_341, vlua_341, target_5)
and func_6(vlua_341, target_6)
and func_7(vc_341, vlua_341, target_7)
and vc_341.getType().hasName("client *")
and vlua_341.getType().hasName("lua_State *")
and vc_341.getParentScope+() = func
and vlua_341.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
