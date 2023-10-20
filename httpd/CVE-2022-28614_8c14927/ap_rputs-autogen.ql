/**
 * @name httpd-8c14927162cf3b4f810683e1c5505e9ef9e1f123-ap_rputs
 * @id cpp/httpd/8c14927162cf3b4f810683e1c5505e9ef9e1f123/ap-rputs
 * @description httpd-8c14927162cf3b4f810683e1c5505e9ef9e1f123-include/http_protocol.h-ap_rputs CVE-2022-28614
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("apr_size_t")
		and target_0.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vr_476, Parameter vstr_476, Function func) {
	exists(ForStmt target_1 |
		target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("apr_size_t")
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2147483647"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("ap_rwrite")
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstr_476
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("apr_size_t")
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vr_476
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ap_rwrite")
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_1))
}

predicate func_3(Parameter vr_476, Parameter vstr_476, FunctionCall target_3) {
		target_3.getTarget().hasName("strlen")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vstr_476
		and target_3.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("ap_rwrite")
		and target_3.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstr_476
		and target_3.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vr_476
}

from Function func, Parameter vr_476, Parameter vstr_476, FunctionCall target_3
where
not func_0(func)
and not func_1(vr_476, vstr_476, func)
and func_3(vr_476, vstr_476, target_3)
and vr_476.getType().hasName("request_rec *")
and vstr_476.getType().hasName("const char *")
and vr_476.getFunction() = func
and vstr_476.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
