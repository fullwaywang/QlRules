/**
 * @name curl-c43127414d-Curl_getconnectinfo
 * @id cpp/curl/c43127414d/Curl-getconnectinfo
 * @description curl-c43127414d-lib/connect.c-Curl_getconnectinfo CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_1121, BlockStmt target_6, ValueFieldAccess target_5) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof ValueFieldAccess
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="multi_easy"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1121
		and target_0.getParent().(IfStmt).getThen()=target_6
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdata_1121, ValueFieldAccess target_5, ValueFieldAccess target_7) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="tofind"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("connfind")
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="lastconnect"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1121
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(ValueFieldAccess target_5, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="found"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("connfind")
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vdata_1121, ValueFieldAccess target_5) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("Curl_conncache_foreach")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="conn_cache"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="multi_easy"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1121
		and target_3.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("connfind")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5)
}

predicate func_4(Parameter vdata_1121, ValueFieldAccess target_5) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="found"
		and target_4.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("connfind")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="lastconnect"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1121
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5)
}

predicate func_5(Parameter vdata_1121, ValueFieldAccess target_5) {
		target_5.getTarget().getName()="lastconnect"
		and target_5.getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1121
}

predicate func_6(BlockStmt target_6) {
		target_6.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sock"
		and target_6.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_6.getStmt(3).(IfStmt).getCondition().(ValueFieldAccess).getTarget().getName()="use"
		and target_6.getStmt(3).(IfStmt).getCondition().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ssl"
		and target_6.getStmt(3).(IfStmt).getCondition().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_6.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getValue()="1"
		and target_6.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_6.getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("recv")
		and target_6.getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_6.getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_7(Parameter vdata_1121, ValueFieldAccess target_7) {
		target_7.getTarget().getName()="lastconnect"
		and target_7.getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1121
}

from Function func, Parameter vdata_1121, ValueFieldAccess target_5, BlockStmt target_6, ValueFieldAccess target_7
where
not func_0(vdata_1121, target_6, target_5)
and not func_1(vdata_1121, target_5, target_7)
and not func_2(target_5, func)
and not func_3(vdata_1121, target_5)
and not func_4(vdata_1121, target_5)
and func_5(vdata_1121, target_5)
and func_6(target_6)
and func_7(vdata_1121, target_7)
and vdata_1121.getType().hasName("SessionHandle *")
and vdata_1121.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
