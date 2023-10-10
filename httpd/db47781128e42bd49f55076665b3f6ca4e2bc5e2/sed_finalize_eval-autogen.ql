/**
 * @name httpd-db47781128e42bd49f55076665b3f6ca4e2bc5e2-sed_finalize_eval
 * @id cpp/httpd/db47781128e42bd49f55076665b3f6ca4e2bc5e2/sed-finalize-eval
 * @description httpd-db47781128e42bd49f55076665b3f6ca4e2bc5e2-sed_finalize_eval CVE-2022-30522
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter veval_438, ExprStmt target_6, ExprStmt target_7) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("apr_status_t")
		and target_0.getRValue().(FunctionCall).getTarget().hasName("append_to_linebuf")
		and target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veval_438
		and target_0.getRValue().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getRValue().(FunctionCall).getArgument(2) instanceof Literal
		and target_6.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(PointerFieldAccess target_8, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("apr_status_t")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(VariableAccess).getType().hasName("apr_status_t")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_1.getEnclosingFunction() = func)
}

predicate func_3(Function func, StringLiteral target_3) {
		target_3.getValue()=""
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, Literal target_4) {
		target_4.getValue()="0"
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Parameter veval_438, FunctionCall target_5) {
		target_5.getTarget().hasName("append_to_linebuf")
		and target_5.getArgument(0).(VariableAccess).getTarget()=veval_438
		and target_5.getArgument(1) instanceof StringLiteral
		and target_5.getArgument(2) instanceof Literal
}

predicate func_6(Parameter veval_438, ExprStmt target_6) {
		target_6.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lspend"
		and target_6.getExpr().(PostfixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veval_438
}

predicate func_7(Parameter veval_438, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lspend"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veval_438
		and target_7.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

predicate func_8(Parameter veval_438, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="lreadyflag"
		and target_8.getQualifier().(VariableAccess).getTarget()=veval_438
}

from Function func, Parameter veval_438, StringLiteral target_3, Literal target_4, FunctionCall target_5, ExprStmt target_6, ExprStmt target_7, PointerFieldAccess target_8
where
not func_0(veval_438, target_6, target_7)
and not func_1(target_8, func)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(veval_438, target_5)
and func_6(veval_438, target_6)
and func_7(veval_438, target_7)
and func_8(veval_438, target_8)
and veval_438.getType().hasName("sed_eval_t *")
and veval_438.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
