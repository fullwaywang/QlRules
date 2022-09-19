import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1092"
		and not target_0.getValue()="1109"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1100"
		and not target_1.getValue()="1117"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="1112"
		and not target_2.getValue()="1129"
		and target_2.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_1(func)
and func_2(func)
select func
