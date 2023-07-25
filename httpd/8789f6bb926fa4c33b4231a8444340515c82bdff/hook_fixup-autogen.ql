/**
 * @name httpd-8789f6bb926fa4c33b4231a8444340515c82bdff-hook_fixup
 * @id cpp/httpd/8789f6bb926fa4c33b4231a8444340515c82bdff/hook-fixup
 * @description httpd-8789f6bb926fa4c33b4231a8444340515c82bdff-modules/mappers/mod_rewrite.c-hook_fixup CVE-2023-25690
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vr_4916, VariableAccess target_1, ExprStmt target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="args"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_4916
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("ap_scan_vchar_obstext")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="args"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_4916
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_log_rerror_")
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="403"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrulestatus_4923, VariableAccess target_1) {
		target_1.getTarget()=vrulestatus_4923
}

predicate func_2(Parameter vr_4916, Variable vrulestatus_4923, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrulestatus_4923
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("apply_rewrite_list")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_4916
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rewriterules"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("rewrite_perdir_conf *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="directory"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("rewrite_perdir_conf *")
}

from Function func, Parameter vr_4916, Variable vrulestatus_4923, VariableAccess target_1, ExprStmt target_2
where
not func_0(vr_4916, target_1, target_2)
and func_1(vrulestatus_4923, target_1)
and func_2(vr_4916, vrulestatus_4923, target_2)
and vr_4916.getType().hasName("request_rec *")
and vrulestatus_4923.getType().hasName("int")
and vr_4916.getFunction() = func
and vrulestatus_4923.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
