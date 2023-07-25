/**
 * @name curl-c43127414d-pop3_state_starttls_resp
 * @id cpp/curl/c43127414d/pop3-state-starttls-resp
 * @description curl-c43127414d-lib/pop3.c-pop3_state_starttls_resp CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_555, Variable vresult_559, EqualityOperation target_6, BlockStmt target_0) {
		target_0.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("state")
		and target_0.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_555
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_559
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_state_upgrade_tls")
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_555
		and target_0.getParent().(IfStmt).getCondition()=target_6
}

predicate func_1(Variable vresult_559, Variable vdata_560, EqualityOperation target_7, IfStmt target_1) {
		target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="used_interface"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_560
		and target_1.getThen() instanceof BlockStmt
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_559
		and target_1.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vresult_559
		and target_1.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_1.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
		and target_1.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_559
		and target_1.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_state_capa")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
}

/*predicate func_2(Variable vresult_559, EqualityOperation target_6, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_559
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

*/
/*predicate func_3(Parameter vconn_555, Variable vresult_559, EqualityOperation target_6, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vresult_559
		and target_3.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_559
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_state_capa")
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_555
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

*/
/*predicate func_4(EqualityOperation target_8, Function func, DoStmt target_4) {
		target_4.getCondition().(Literal).getValue()="0"
		and target_4.getStmt().(BlockStmt).toString() = "{ ... }"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_4.getEnclosingFunction() = func
}

*/
/*predicate func_5(Parameter vconn_555, Variable vresult_559, EqualityOperation target_8, ExprStmt target_9, ReturnStmt target_10, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_559
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_state_capa")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_555
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getExpr().(VariableAccess).getLocation())
}

*/
predicate func_6(EqualityOperation target_6) {
		target_6.getAnOperand() instanceof ValueFieldAccess
		and target_6.getAnOperand() instanceof EnumConstantAccess
}

predicate func_7(EqualityOperation target_7) {
		target_7.getAnOperand().(CharLiteral).getValue()="43"
}

predicate func_8(Variable vresult_559, EqualityOperation target_8) {
		target_8.getAnOperand() instanceof EnumConstantAccess
		and target_8.getAnOperand().(VariableAccess).getTarget()=vresult_559
}

predicate func_9(Parameter vconn_555, Variable vresult_559, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_559
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pop3_state_upgrade_tls")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_555
}

predicate func_10(Variable vresult_559, ReturnStmt target_10) {
		target_10.getExpr().(VariableAccess).getTarget()=vresult_559
}

from Function func, Parameter vconn_555, Variable vresult_559, Variable vdata_560, BlockStmt target_0, IfStmt target_1, EqualityOperation target_6, EqualityOperation target_7, EqualityOperation target_8, ExprStmt target_9, ReturnStmt target_10
where
func_0(vconn_555, vresult_559, target_6, target_0)
and func_1(vresult_559, vdata_560, target_7, target_1)
and func_6(target_6)
and func_7(target_7)
and func_8(vresult_559, target_8)
and func_9(vconn_555, vresult_559, target_9)
and func_10(vresult_559, target_10)
and vconn_555.getType().hasName("connectdata *")
and vresult_559.getType().hasName("CURLcode")
and vdata_560.getType().hasName("SessionHandle *")
and vconn_555.getParentScope+() = func
and vresult_559.getParentScope+() = func
and vdata_560.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
