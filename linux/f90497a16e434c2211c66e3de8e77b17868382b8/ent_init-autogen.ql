/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-ent_init
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/ent-init
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-ent_init 
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

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("strscpy")
		and target_1.getArgument(0) instanceof PointerFieldAccess
		and target_1.getArgument(1) instanceof PointerFieldAccess
		and target_1.getArgument(2) instanceof SizeofExprOperator
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vnew_79) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="name"
		and target_2.getQualifier().(VariableAccess).getTarget()=vnew_79
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_3(Variable vitm_80) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="name"
		and target_3.getQualifier().(VariableAccess).getTarget()=vitm_80
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_4(Variable vnew_79) {
	exists(SizeofExprOperator target_4 |
		target_4.getValue()="128"
		and target_4.getExprOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_4.getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_79)
}

predicate func_5(Variable vnew_79) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="authname"
		and target_5.getQualifier().(VariableAccess).getTarget()=vnew_79
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_6(Variable vitm_80) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="authname"
		and target_6.getQualifier().(VariableAccess).getTarget()=vitm_80
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_7(Variable vnew_79) {
	exists(SizeofExprOperator target_7 |
		target_7.getValue()="128"
		and target_7.getExprOperand().(PointerFieldAccess).getTarget().getName()="authname"
		and target_7.getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_79)
}

predicate func_8(Function func) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("strlcpy")
		and target_8.getArgument(0) instanceof PointerFieldAccess
		and target_8.getArgument(1) instanceof PointerFieldAccess
		and target_8.getArgument(2) instanceof SizeofExprOperator
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("strlcpy")
		and target_9.getArgument(0) instanceof PointerFieldAccess
		and target_9.getArgument(1) instanceof PointerFieldAccess
		and target_9.getArgument(2) instanceof SizeofExprOperator
		and target_9.getEnclosingFunction() = func)
}

from Function func, Variable vnew_79, Variable vitm_80
where
not func_0(func)
and not func_1(func)
and func_2(vnew_79)
and func_3(vitm_80)
and func_4(vnew_79)
and func_5(vnew_79)
and func_6(vitm_80)
and func_7(vnew_79)
and func_8(func)
and func_9(func)
and vnew_79.getType().hasName("ent *")
and vitm_80.getType().hasName("ent *")
and vnew_79.getParentScope+() = func
and vitm_80.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
