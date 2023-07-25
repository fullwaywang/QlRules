/**
 * @name httpd-8789f6bb926fa4c33b4231a8444340515c82bdff-proxy_wstunnel_canon
 * @id cpp/httpd/8789f6bb926fa4c33b4231a8444340515c82bdff/proxy-wstunnel-canon
 * @description httpd-8789f6bb926fa4c33b4231a8444340515c82bdff-modules/proxy/mod_proxy_wstunnel.c-proxy_wstunnel_canon CVE-2023-25690
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsearch_66, FunctionCall target_1, ExprStmt target_2, ConditionalExpr target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vsearch_66
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("ap_scan_vchar_obstext")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsearch_66
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_log_rerror_")
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="403"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(VariableAccess).getLocation()))
}

predicate func_1(FunctionCall target_1) {
		target_1.getTarget().hasName("apr_table_get")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="notes"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("request_rec *")
		and target_1.getArgument(1).(StringLiteral).getValue()="proxy-nocanon"
}

predicate func_2(Variable vsearch_66, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsearch_66
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="args"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("request_rec *")
}

predicate func_3(Variable vsearch_66, ConditionalExpr target_3) {
		target_3.getCondition().(VariableAccess).getTarget()=vsearch_66
		and target_3.getThen().(StringLiteral).getValue()="?"
		and target_3.getElse().(StringLiteral).getValue()=""
}

from Function func, Variable vsearch_66, FunctionCall target_1, ExprStmt target_2, ConditionalExpr target_3
where
not func_0(vsearch_66, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vsearch_66, target_2)
and func_3(vsearch_66, target_3)
and vsearch_66.getType().hasName("char *")
and vsearch_66.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
