import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1"
		and not target_0.getValue()="2"
		and target_0.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
select func
