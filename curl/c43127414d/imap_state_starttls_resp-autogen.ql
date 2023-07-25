/**
 * @name curl-c43127414d-imap_state_starttls_resp
 * @id cpp/curl/c43127414d/imap-state-starttls-resp
 * @description curl-c43127414d-lib/imap.c-imap_state_starttls_resp CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_9, Function func) {
	exists(ReturnStmt target_0 |
		target_0.getExpr() instanceof FunctionCall
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vconn_618, EqualityOperation target_10, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("state")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_618
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_2(Parameter vconn_618, FunctionCall target_2) {
		target_2.getTarget().hasName("imap_state_upgrade_tls")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vconn_618
}

predicate func_3(Variable vresult_622, Variable vdata_623, EqualityOperation target_9, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_623
		and target_3.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_622
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_622
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vresult_622
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_622
		and target_3.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("imap_state_capability")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_4(Variable vresult_622, EqualityOperation target_10, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_622
		and target_4.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

/*predicate func_5(Variable vresult_622, EqualityOperation target_10, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_622
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

*/
/*predicate func_6(Parameter vconn_618, Variable vresult_622, EqualityOperation target_10, IfStmt target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vresult_622
		and target_6.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_622
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("imap_state_capability")
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_618
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

*/
/*predicate func_7(EqualityOperation target_11, Function func, DoStmt target_7) {
		target_7.getCondition().(Literal).getValue()="0"
		and target_7.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_7.getEnclosingFunction() = func
}

*/
/*predicate func_8(Parameter vconn_618, Variable vresult_622, EqualityOperation target_11, ExprStmt target_4, ReturnStmt target_12, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_622
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("imap_state_capability")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_618
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_12.getExpr().(VariableAccess).getLocation())
}

*/
predicate func_9(EqualityOperation target_9) {
		target_9.getAnOperand().(CharLiteral).getValue()="79"
}

predicate func_10(EqualityOperation target_10) {
		target_10.getAnOperand() instanceof ValueFieldAccess
		and target_10.getAnOperand() instanceof EnumConstantAccess
}

predicate func_11(Variable vresult_622, EqualityOperation target_11) {
		target_11.getAnOperand() instanceof EnumConstantAccess
		and target_11.getAnOperand().(VariableAccess).getTarget()=vresult_622
}

predicate func_12(Variable vresult_622, ReturnStmt target_12) {
		target_12.getExpr().(VariableAccess).getTarget()=vresult_622
}

from Function func, Parameter vconn_618, Variable vresult_622, Variable vdata_623, ExprStmt target_1, FunctionCall target_2, IfStmt target_3, ExprStmt target_4, EqualityOperation target_9, EqualityOperation target_10, EqualityOperation target_11, ReturnStmt target_12
where
not func_0(target_9, func)
and func_1(vconn_618, target_10, target_1)
and func_2(vconn_618, target_2)
and func_3(vresult_622, vdata_623, target_9, target_3)
and func_4(vresult_622, target_10, target_4)
and func_9(target_9)
and func_10(target_10)
and func_11(vresult_622, target_11)
and func_12(vresult_622, target_12)
and vconn_618.getType().hasName("connectdata *")
and vresult_622.getType().hasName("CURLcode")
and vdata_623.getType().hasName("SessionHandle *")
and vconn_618.getParentScope+() = func
and vresult_622.getParentScope+() = func
and vdata_623.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
