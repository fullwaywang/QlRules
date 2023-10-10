/**
 * @name curl-c43127414d-ftp_state_pasv_resp
 * @id cpp/curl/c43127414d/ftp-state-pasv-resp
 * @description curl-c43127414d-lib/ftp.c-ftp_state_pasv_resp CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_1813, FunctionCall target_0) {
		target_0.getTarget().hasName("state")
		and not target_0.getTarget().hasName("_state")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vconn_1813
}

predicate func_1(Parameter vconn_1813, LogicalAndExpr target_6, ExprStmt target_7) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tunnel_state"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1813
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_state")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1813
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="tcpconnect"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(7)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vconn_1813, ExprStmt target_8, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="do_more"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1813
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_2)
		and target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vconn_1813, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("_state")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1813
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_3))
}

predicate func_4(Variable vresult_1817, ReturnStmt target_10, ReturnStmt target_5, Function func) {
	exists(ReturnStmt target_4 |
		target_4.getExpr().(VariableAccess).getTarget()=vresult_1817
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_4)
		and target_10.getExpr().(VariableAccess).getLocation().isBefore(target_4.getExpr().(VariableAccess).getLocation())
		and target_4.getExpr().(VariableAccess).getLocation().isBefore(target_5.getExpr().(VariableAccess).getLocation()))
}

predicate func_5(Variable vresult_1817, Function func, ReturnStmt target_5) {
		target_5.getExpr().(VariableAccess).getTarget()=vresult_1817
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Parameter vconn_1813, LogicalAndExpr target_6) {
		target_6.getAnOperand().(ValueFieldAccess).getTarget().getName()="tunnel_proxy"
		and target_6.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_6.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1813
		and target_6.getAnOperand().(ValueFieldAccess).getTarget().getName()="httpproxy"
		and target_6.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_6.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1813
}

predicate func_7(Parameter vconn_1813, Variable vresult_1817, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_1817
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_proxyCONNECT")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1813
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="1"
}

predicate func_8(Parameter vconn_1813, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="tcpconnect"
		and target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bits"
		and target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1813
		and target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_10(Variable vresult_1817, ReturnStmt target_10) {
		target_10.getExpr().(VariableAccess).getTarget()=vresult_1817
}

from Function func, Parameter vconn_1813, Variable vresult_1817, FunctionCall target_0, ReturnStmt target_5, LogicalAndExpr target_6, ExprStmt target_7, ExprStmt target_8, ReturnStmt target_10
where
func_0(vconn_1813, target_0)
and not func_1(vconn_1813, target_6, target_7)
and not func_2(vconn_1813, target_8, func)
and not func_3(vconn_1813, func)
and not func_4(vresult_1817, target_10, target_5, func)
and func_5(vresult_1817, func, target_5)
and func_6(vconn_1813, target_6)
and func_7(vconn_1813, vresult_1817, target_7)
and func_8(vconn_1813, target_8)
and func_10(vresult_1817, target_10)
and vconn_1813.getType().hasName("connectdata *")
and vresult_1817.getType().hasName("CURLcode")
and vconn_1813.getParentScope+() = func
and vresult_1817.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
