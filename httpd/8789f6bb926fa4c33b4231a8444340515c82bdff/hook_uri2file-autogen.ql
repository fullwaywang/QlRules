/**
 * @name httpd-8789f6bb926fa4c33b4231a8444340515c82bdff-hook_uri2file
 * @id cpp/httpd/8789f6bb926fa4c33b4231a8444340515c82bdff/hook-uri2file
 * @description httpd-8789f6bb926fa4c33b4231a8444340515c82bdff-modules/mappers/mod_rewrite.c-hook_uri2file CVE-2023-25690
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vr_4593, VariableAccess target_1, ExprStmt target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="args"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_4593
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("ap_scan_vchar_obstext")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="args"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_4593
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ap_log_rerror_")
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="403"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrulestatus_4603, VariableAccess target_1) {
		target_1.getTarget()=vrulestatus_4603
}

predicate func_2(Parameter vr_4593, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("do_rewritelog")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_4593
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_2.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_2.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="uri already rewritten. Status %s, Uri %s, r->filename %s"
		and target_2.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_2.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="uri"
		and target_2.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_4593
		and target_2.getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="filename"
		and target_2.getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_4593
}

from Function func, Parameter vr_4593, Variable vrulestatus_4603, VariableAccess target_1, ExprStmt target_2
where
not func_0(vr_4593, target_1, target_2)
and func_1(vrulestatus_4603, target_1)
and func_2(vr_4593, target_2)
and vr_4593.getType().hasName("request_rec *")
and vrulestatus_4603.getType().hasName("int")
and vr_4593.getFunction() = func
and vrulestatus_4603.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
