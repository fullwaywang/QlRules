import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="550"
		and not target_0.getValue()="570"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="556"
		and not target_1.getValue()="576"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="562"
		and not target_2.getValue()="582"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="570"
		and not target_3.getValue()="590"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="579"
		and not target_4.getValue()="599"
		and target_4.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
select func
