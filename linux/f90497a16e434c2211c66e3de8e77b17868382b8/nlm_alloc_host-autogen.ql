/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nlm_alloc_host
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nlm-alloc-host
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nlm_alloc_host 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("strscpy")
		and target_0.getArgument(0) instanceof PointerFieldAccess
		and target_0.getArgument(1) instanceof PointerFieldAccess
		and target_0.getArgument(2) instanceof SizeofExprOperator
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vhost_114) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="nodename"
		and target_1.getQualifier().(VariableAccess).getTarget()=vhost_114
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_2(Function func) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="nodename"
		and target_2.getQualifier().(FunctionCall).getTarget().hasName("utsname")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vhost_114) {
	exists(SizeofExprOperator target_3 |
		target_3.getValue()="65"
		and target_3.getExprOperand().(PointerFieldAccess).getTarget().getName()="nodename"
		and target_3.getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhost_114)
}

predicate func_4(Function func) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("strlcpy")
		and target_4.getArgument(0) instanceof PointerFieldAccess
		and target_4.getArgument(1) instanceof PointerFieldAccess
		and target_4.getArgument(2) instanceof SizeofExprOperator
		and target_4.getEnclosingFunction() = func)
}

from Function func, Variable vhost_114
where
not func_0(func)
and func_1(vhost_114)
and func_2(func)
and func_3(vhost_114)
and func_4(func)
and vhost_114.getType().hasName("nlm_host *")
and vhost_114.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
