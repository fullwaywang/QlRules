import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1064"
		and not target_0.getValue()="1076"
		and target_0.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
select func
