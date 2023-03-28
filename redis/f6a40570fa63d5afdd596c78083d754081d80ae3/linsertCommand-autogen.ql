/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-linsertCommand
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/linsertCommand
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-linsertCommand CVE-2021-32627 CVE-2021-32628
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vc_264, ExprStmt target_3, LogicalOrExpr target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_264
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="4"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294966272"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_264
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Element too large"
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Function func, ReturnStmt target_2) {
		target_2.toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter vc_264, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("addReply")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_264
		and target_3.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="syntaxerr"
		and target_3.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("sharedObjectsStruct")
}

predicate func_4(Parameter vc_264, LogicalOrExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("robj *")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lookupKeyWriteOrReply")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_264
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_264
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="czero"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("sharedObjectsStruct")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(FunctionCall).getTarget().hasName("checkType")
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_264
		and target_4.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("robj *")
		and target_4.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="1"
}

from Function func, Parameter vc_264, ReturnStmt target_2, ExprStmt target_3, LogicalOrExpr target_4
where
not func_0(vc_264, target_3, target_4, func)
and func_2(func, target_2)
and func_3(vc_264, target_3)
and func_4(vc_264, target_4)
and vc_264.getType().hasName("client *")
and vc_264.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
