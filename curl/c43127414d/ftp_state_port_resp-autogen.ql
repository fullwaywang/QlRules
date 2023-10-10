/**
 * @name curl-c43127414d-ftp_state_port_resp
 * @id cpp/curl/c43127414d/ftp-state-port-resp
 * @description curl-c43127414d-lib/ftp.c-ftp_state_port_resp CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_2083, FunctionCall target_0) {
		target_0.getTarget().hasName("state")
		and not target_0.getTarget().hasName("_state")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vconn_2083
}

predicate func_1(Parameter vconn_2083, Variable vresult_2089, EqualityOperation target_2, ExprStmt target_4, ReturnStmt target_5) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_2089
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ftp_dophase_done")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_2083
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(VariableAccess).getLocation()))
}

predicate func_2(EqualityOperation target_2) {
		target_2.getAnOperand().(Literal).getValue()="200"
}

predicate func_4(Parameter vconn_2083, Variable vresult_2089, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_2089
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ftp_state_use_port")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_2083
}

predicate func_5(Variable vresult_2089, ReturnStmt target_5) {
		target_5.getExpr().(VariableAccess).getTarget()=vresult_2089
}

from Function func, Parameter vconn_2083, Variable vresult_2089, FunctionCall target_0, EqualityOperation target_2, ExprStmt target_4, ReturnStmt target_5
where
func_0(vconn_2083, target_0)
and not func_1(vconn_2083, vresult_2089, target_2, target_4, target_5)
and func_2(target_2)
and func_4(vconn_2083, vresult_2089, target_4)
and func_5(vresult_2089, target_5)
and vconn_2083.getType().hasName("connectdata *")
and vresult_2089.getType().hasName("CURLcode")
and vconn_2083.getParentScope+() = func
and vresult_2089.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
