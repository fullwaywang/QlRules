/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-lremCommand
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/lremCommand
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-lremCommand CVE-2021-32627 CVE-2021-32628
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vobj_608, Parameter vc_607, ExprStmt target_3, FunctionCall target_4, EqualityOperation target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobj_608
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294966272"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_607
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Element too large"
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getArgument(1).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Function func, ReturnStmt target_2) {
		target_2.toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vobj_608, Parameter vc_607, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vobj_608
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_607
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
}

predicate func_4(Variable vobj_608, FunctionCall target_4) {
		target_4.getTarget().hasName("listTypeEqual")
		and target_4.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("listTypeEntry")
		and target_4.getArgument(1).(VariableAccess).getTarget()=vobj_608
}

predicate func_5(Parameter vc_607, EqualityOperation target_5) {
		target_5.getAnOperand().(FunctionCall).getTarget().hasName("getLongFromObjectOrReply")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_607
		and target_5.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_5.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_607
		and target_5.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_5.getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("long")
		and target_5.getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_5.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vobj_608, Parameter vc_607, ReturnStmt target_2, ExprStmt target_3, FunctionCall target_4, EqualityOperation target_5
where
not func_0(vobj_608, vc_607, target_3, target_4, target_5, func)
and func_2(func, target_2)
and func_3(vobj_608, vc_607, target_3)
and func_4(vobj_608, target_4)
and func_5(vc_607, target_5)
and vobj_608.getType().hasName("robj *")
and vc_607.getType().hasName("client *")
and vobj_608.getParentScope+() = func
and vc_607.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
