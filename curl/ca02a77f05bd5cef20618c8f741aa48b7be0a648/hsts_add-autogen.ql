/**
 * @name curl-ca02a77f05bd5cef20618c8f741aa48b7be0a648-hsts_add
 * @id cpp/curl/ca02a77f05bd5cef20618c8f741aa48b7be0a648/hsts-add
 * @description curl-ca02a77f05bd5cef20618c8f741aa48b7be0a648-lib/hsts.c-hsts_add CVE-2023-23914
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vp_430, Variable vsubdomain_431, Parameter vh_413, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_3, ExprStmt target_6) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("stsentry *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_hsts")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vh_413
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_430
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsubdomain_431
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_2(Variable vexpires_427, EqualityOperation target_4, ExprStmt target_3) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("stsentry *")
		and target_2.getThen() instanceof ExprStmt
		and target_2.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vexpires_427
		and target_2.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="expires"
		and target_2.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("stsentry *")
		and target_2.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="expires"
		and target_2.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("stsentry *")
		and target_2.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vexpires_427
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(7)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_2.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_3(Variable vexpires_427, Variable vresult_429, Variable vp_430, Variable vsubdomain_431, Parameter vh_413, EqualityOperation target_4, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_429
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("hsts_create")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vh_413
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_430
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsubdomain_431
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vexpires_427
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_4(EqualityOperation target_4) {
		target_4.getAnOperand().(Literal).getValue()="2"
}

predicate func_5(Variable vp_430, ExprStmt target_5) {
		target_5.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_430
}

predicate func_6(Variable vsubdomain_431, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsubdomain_431
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Variable vexpires_427, Variable vresult_429, Variable vp_430, Variable vsubdomain_431, Parameter vh_413, ExprStmt target_3, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_6
where
not func_1(vp_430, vsubdomain_431, vh_413, target_4, target_5, target_3, target_6)
and not func_2(vexpires_427, target_4, target_3)
and func_3(vexpires_427, vresult_429, vp_430, vsubdomain_431, vh_413, target_4, target_3)
and func_4(target_4)
and func_5(vp_430, target_5)
and func_6(vsubdomain_431, target_6)
and vexpires_427.getType().hasName("time_t")
and vresult_429.getType().hasName("CURLcode")
and vp_430.getType().hasName("char *")
and vsubdomain_431.getType().hasName("bool")
and vh_413.getType().hasName("hsts *")
and vexpires_427.getParentScope+() = func
and vresult_429.getParentScope+() = func
and vp_430.getParentScope+() = func
and vsubdomain_431.getParentScope+() = func
and vh_413.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()