import cpp

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="512"
		and target_1.getEnclosingFunction() = func)
}

from Function func, Variable vstate
where
func_1(func)
and vstate.getType().hasName("tftp_state_data_t *")
and vstate.getParentScope+() = func
select func, vstate
