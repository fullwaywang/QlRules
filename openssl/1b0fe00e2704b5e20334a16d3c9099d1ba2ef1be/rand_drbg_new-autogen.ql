import cpp

predicate func_0(Variable vdrbg) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="fork_count"
		and target_0.getType().hasName("int")
		and target_0.getQualifier().(VariableAccess).getTarget()=vdrbg)
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("openssl_get_fork_id")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(VariableAccess target_2 |
		target_2.getParent().(AssignExpr).getLValue() instanceof PointerFieldAccess
		and target_2.getEnclosingFunction() = func)
}

from Function func, Variable vdrbg
where
func_0(vdrbg)
and not func_1(func)
and func_2(func)
and vdrbg.getType().hasName("RAND_DRBG *")
and vdrbg.getParentScope+() = func
select func, vdrbg
