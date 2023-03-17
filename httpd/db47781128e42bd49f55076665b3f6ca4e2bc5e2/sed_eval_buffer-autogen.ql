/**
 * @name httpd-db47781128e42bd49f55076665b3f6ca4e2bc5e2-sed_eval_buffer
 * @id cpp/httpd/db47781128e42bd49f55076665b3f6ca4e2bc5e2/sed-eval-buffer
 * @description httpd-db47781128e42bd49f55076665b3f6ca4e2bc5e2-sed_eval_buffer CVE-2022-30522
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter veval_371, Parameter vbuf_371, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("apr_status_t")
		and target_0.getRValue().(FunctionCall).getTarget().hasName("appendmem_to_linebuf")
		and target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veval_371
		and target_0.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_371
		and target_0.getRValue().(FunctionCall).getArgument(2) instanceof AddExpr
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_13.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("apr_status_t")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(VariableAccess).getType().hasName("apr_status_t")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(VariableAccess target_16, Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(VariableAccess).getType().hasName("apr_status_t")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(VariableAccess target_16, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("apr_status_t")
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(VariableAccess).getType().hasName("apr_status_t")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vllen_401, AddExpr target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vllen_401
		and target_4.getAnOperand().(Literal).getValue()="1"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_10(Parameter veval_371, Parameter vbuf_371, FunctionCall target_10) {
		target_10.getTarget().hasName("appendmem_to_linebuf")
		and target_10.getArgument(0).(VariableAccess).getTarget()=veval_371
		and target_10.getArgument(1).(VariableAccess).getTarget()=vbuf_371
		and target_10.getArgument(2) instanceof AddExpr
}

predicate func_11(Parameter veval_371, Parameter vbuf_371, Parameter vbufsz_371, VariableAccess target_16, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("appendmem_to_linebuf")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veval_371
		and target_11.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_371
		and target_11.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbufsz_371
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
}

predicate func_12(Parameter veval_371, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="lreadyflag"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veval_371
		and target_12.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_13(Parameter veval_371, ExprStmt target_13) {
		target_13.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lspend"
		and target_13.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veval_371
}

predicate func_14(Parameter vbuf_371, Variable vllen_401, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vllen_401
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vbuf_371
}

predicate func_15(Parameter vbuf_371, Variable vllen_401, ExprStmt target_15) {
		target_15.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vbuf_371
		and target_15.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vllen_401
		and target_15.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_16(Parameter vbufsz_371, VariableAccess target_16) {
		target_16.getTarget()=vbufsz_371
}

from Function func, Parameter veval_371, Parameter vbuf_371, Parameter vbufsz_371, Variable vllen_401, AddExpr target_4, FunctionCall target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, VariableAccess target_16
where
not func_0(veval_371, vbuf_371, target_12, target_13, target_14, target_15)
and not func_1(func)
and not func_2(target_16, func)
and not func_3(target_16, func)
and func_4(vllen_401, target_4)
and func_10(veval_371, vbuf_371, target_10)
and func_11(veval_371, vbuf_371, vbufsz_371, target_16, target_11)
and func_12(veval_371, target_12)
and func_13(veval_371, target_13)
and func_14(vbuf_371, vllen_401, target_14)
and func_15(vbuf_371, vllen_401, target_15)
and func_16(vbufsz_371, target_16)
and veval_371.getType().hasName("sed_eval_t *")
and vbuf_371.getType().hasName("const char *")
and vbufsz_371.getType().hasName("apr_size_t")
and vllen_401.getType().hasName("apr_size_t")
and veval_371.getParentScope+() = func
and vbuf_371.getParentScope+() = func
and vbufsz_371.getParentScope+() = func
and vllen_401.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
