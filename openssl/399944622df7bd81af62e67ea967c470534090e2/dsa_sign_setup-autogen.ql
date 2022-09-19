import cpp

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="256"
		and not target_1.getValue()="257"
		and target_1.getEnclosingFunction() = func)
}

from Function func, Variable vK, Parameter vdsa
where
func_1(func)
and vK.getType().hasName("BIGNUM *")
and vdsa.getType().hasName("DSA *")
and vK.getParentScope+() = func
and vdsa.getParentScope+() = func
select func, vK, vdsa
