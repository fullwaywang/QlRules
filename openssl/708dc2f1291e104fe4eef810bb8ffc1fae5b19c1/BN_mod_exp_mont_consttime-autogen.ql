import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="677"
		and not target_0.getValue()="716"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="774"
		and not target_1.getValue()="813"
		and target_1.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_1(func)
select func
