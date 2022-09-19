import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="210"
		and not target_0.getValue()="212"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vrsa, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("BN_set_flags")
		and target_1.getExpr().(FunctionCall).getType().hasName("void")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="p"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("BIGNUM *")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsa
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Parameter vrsa, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("BN_set_flags")
		and target_2.getExpr().(FunctionCall).getType().hasName("void")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="q"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("BIGNUM *")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsa
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

from Function func, Parameter vrsa
where
func_0(func)
and not func_1(vrsa, func)
and not func_2(vrsa, func)
and vrsa.getType().hasName("RSA *")
and vrsa.getParentScope+() = func
select func, vrsa
