/**
 * @name httpd-db47781128e42bd49f55076665b3f6ca4e2bc5e2-place
 * @id cpp/httpd/db47781128e42bd49f55076665b3f6ca4e2bc5e2/place
 * @description httpd-db47781128e42bd49f55076665b3f6ca4e2bc5e2-place CVE-2022-30522
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(RelationalOperation target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("apr_status_t")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vsp_693, AddressOfExpr target_1) {
		target_1.getOperand().(VariableAccess).getTarget()=vsp_693
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_4(Variable vreqsize_695, Parameter veval_691, RelationalOperation target_5, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("grow_gen_buffer")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veval_691
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vreqsize_695
		and target_4.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_5(Variable vreqsize_695, Parameter veval_691, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(PointerFieldAccess).getTarget().getName()="gsize"
		and target_5.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=veval_691
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vreqsize_695
}

from Function func, Variable vreqsize_695, Parameter veval_691, Variable vsp_693, AddressOfExpr target_1, ExprStmt target_4, RelationalOperation target_5
where
not func_0(target_5, func)
and func_1(vsp_693, target_1)
and func_4(vreqsize_695, veval_691, target_5, target_4)
and func_5(vreqsize_695, veval_691, target_5)
and vreqsize_695.getType().hasName("apr_size_t")
and veval_691.getType().hasName("sed_eval_t *")
and vsp_693.getType().hasName("char *")
and vreqsize_695.getParentScope+() = func
and veval_691.getParentScope+() = func
and vsp_693.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
