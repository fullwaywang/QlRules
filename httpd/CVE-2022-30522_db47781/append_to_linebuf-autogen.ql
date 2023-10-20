/**
 * @name httpd-db47781128e42bd49f55076665b3f6ca4e2bc5e2-append_to_linebuf
 * @id cpp/httpd/db47781128e42bd49f55076665b3f6ca4e2bc5e2/append-to-linebuf
 * @description httpd-db47781128e42bd49f55076665b3f6ca4e2bc5e2-append_to_linebuf CVE-2022-30522
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter veval_172, Parameter vsz_172, ExprStmt target_7, FunctionCall target_8) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("apr_status_t")
		and target_0.getRValue().(FunctionCall).getTarget().hasName("appendmem_to_linebuf")
		and target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veval_172
		and target_0.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsz_172
		and target_0.getRValue().(FunctionCall).getArgument(2) instanceof AddExpr
		and target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("apr_status_t")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(VariableAccess).getType().hasName("apr_status_t")
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1))
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="0"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vlen_175, AddExpr target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vlen_175
		and target_3.getAnOperand().(Literal).getValue()="1"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Parameter veval_172, Parameter vsz_172, FunctionCall target_6) {
		target_6.getTarget().hasName("appendmem_to_linebuf")
		and target_6.getArgument(0).(VariableAccess).getTarget()=veval_172
		and target_6.getArgument(1).(VariableAccess).getTarget()=vsz_172
		and target_6.getArgument(2) instanceof AddExpr
}

predicate func_7(Parameter veval_172, ExprStmt target_7) {
		target_7.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lspend"
		and target_7.getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veval_172
}

predicate func_8(Parameter vsz_172, FunctionCall target_8) {
		target_8.getTarget().hasName("strlen")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vsz_172
}

from Function func, Variable vlen_175, Parameter veval_172, Parameter vsz_172, AddExpr target_3, FunctionCall target_6, ExprStmt target_7, FunctionCall target_8
where
not func_0(veval_172, vsz_172, target_7, target_8)
and not func_1(func)
and not func_2(func)
and func_3(vlen_175, target_3)
and func_6(veval_172, vsz_172, target_6)
and func_7(veval_172, target_7)
and func_8(vsz_172, target_8)
and vlen_175.getType().hasName("apr_size_t")
and veval_172.getType().hasName("sed_eval_t *")
and vsz_172.getType().hasName("const char *")
and vlen_175.getParentScope+() = func
and veval_172.getParentScope+() = func
and vsz_172.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
