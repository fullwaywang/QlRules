/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-lremCommand
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/lremCommand
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-src/t_list.c-lremCommand CVE-2021-32627
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vobj_608, Parameter vc_607, ExprStmt target_1, FunctionCall target_2, EqualityOperation target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobj_608
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294966272"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_607
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Element too large"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getArgument(1).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vobj_608, Parameter vc_607, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vobj_608
		and target_1.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_1.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_607
		and target_1.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
}

predicate func_2(Variable vobj_608, FunctionCall target_2) {
		target_2.getTarget().hasName("listTypeEqual")
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("listTypeEntry")
		and target_2.getArgument(1).(VariableAccess).getTarget()=vobj_608
}

predicate func_3(Parameter vc_607, EqualityOperation target_3) {
		target_3.getAnOperand().(FunctionCall).getTarget().hasName("getLongFromObjectOrReply")
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_607
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_607
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_3.getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("long")
		and target_3.getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_3.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vobj_608, Parameter vc_607, ExprStmt target_1, FunctionCall target_2, EqualityOperation target_3
where
not func_0(vobj_608, vc_607, target_1, target_2, target_3, func)
and func_1(vobj_608, vc_607, target_1)
and func_2(vobj_608, target_2)
and func_3(vc_607, target_3)
and vobj_608.getType().hasName("robj *")
and vc_607.getType().hasName("client *")
and vobj_608.(LocalVariable).getFunction() = func
and vc_607.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
