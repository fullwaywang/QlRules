import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1180"
		and not target_0.getValue()="1200"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1188"
		and not target_1.getValue()="1208"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="1200"
		and not target_2.getValue()="1220"
		and target_2.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_1(func)
and func_2(func)
select func
