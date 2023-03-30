/**
 * @name memcached-bd578fc34b96abe0f8d99c1409814a09f51ee71c-dispatch_bin_command
 * @id cpp/memcached/bd578fc34b96abe0f8d99c1409814a09f51ee71c-dispatch-bin-command
 * @description memcached-bd578fc34b96abe0f8d99c1409814a09f51ee71c-memcached.c-dispatch_bin_command CVE-2016-8706
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vc_1997, Variable vextlen_2000, Variable vkeylen_2001, Variable vbodylen_2002, ValueFieldAccess target_3, LogicalAndExpr target_4, LogicalAndExpr target_5, RelationalOperation target_6, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vkeylen_2001
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbodylen_2002
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vkeylen_2001
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vextlen_2000
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbodylen_2002
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("write_bin_error")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_1997
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="write_and_go"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1997
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_2)
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vc_1997, ValueFieldAccess target_3) {
		target_3.getTarget().getName()="request"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="binary_header"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1997
}

predicate func_4(Parameter vc_1997, LogicalAndExpr target_4) {
		target_4.getAnOperand().(ValueFieldAccess).getTarget().getName()="sasl"
		and target_4.getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("settings")
		and target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("authenticated")
		and target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_1997
}

predicate func_5(Variable vextlen_2000, Variable vkeylen_2001, Variable vbodylen_2002, LogicalAndExpr target_5) {
		target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vextlen_2000
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vkeylen_2001
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbodylen_2002
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_6(Variable vkeylen_2001, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vkeylen_2001
		and target_6.getLesserOperand().(Literal).getValue()="250"
}

from Function func, Parameter vc_1997, Variable vextlen_2000, Variable vkeylen_2001, Variable vbodylen_2002, ValueFieldAccess target_3, LogicalAndExpr target_4, LogicalAndExpr target_5, RelationalOperation target_6
where
not func_2(vc_1997, vextlen_2000, vkeylen_2001, vbodylen_2002, target_3, target_4, target_5, target_6, func)
and func_3(vc_1997, target_3)
and func_4(vc_1997, target_4)
and func_5(vextlen_2000, vkeylen_2001, vbodylen_2002, target_5)
and func_6(vkeylen_2001, target_6)
and vc_1997.getType().hasName("conn *")
and vextlen_2000.getType().hasName("int")
and vkeylen_2001.getType().hasName("int")
and vbodylen_2002.getType().hasName("uint32_t")
and vc_1997.getFunction() = func
and vextlen_2000.getParentScope+() = func
and vkeylen_2001.getParentScope+() = func
and vbodylen_2002.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
