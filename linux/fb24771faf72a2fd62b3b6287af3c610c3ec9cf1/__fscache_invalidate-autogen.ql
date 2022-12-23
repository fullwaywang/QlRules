/**
 * @name linux-fb24771faf72a2fd62b3b6287af3c610c3ec9cf1-__fscache_invalidate
 * @id cpp/linux/fb24771faf72a2fd62b3b6287af3c610c3ec9cf1/__fscache_invalidate
 * @description linux-fb24771faf72a2fd62b3b6287af3c610c3ec9cf1-__fscache_invalidate 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_and_set_bit")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof AddressOfExpr
		and target_0.getThen() instanceof ExprStmt
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vcookie_1034) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("__fscache_begin_cookie_access")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcookie_1034)
}

predicate func_2(Parameter vcookie_1034) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcookie_1034
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="15"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("set_bit")
		and target_4.getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_4.getExpr().(FunctionCall).getArgument(1) instanceof AddressOfExpr
		and target_4.getEnclosingFunction() = func)
}

from Function func, Parameter vcookie_1034
where
not func_0(func)
and func_1(vcookie_1034)
and func_2(vcookie_1034)
and func_3(func)
and func_4(func)
and vcookie_1034.getType().hasName("fscache_cookie *")
and vcookie_1034.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
