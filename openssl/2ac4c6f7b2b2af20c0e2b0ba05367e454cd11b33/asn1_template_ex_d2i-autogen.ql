import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="448"
		and not target_0.getValue()="464"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="454"
		and not target_1.getValue()="470"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="460"
		and not target_2.getValue()="476"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="468"
		and not target_3.getValue()="484"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="477"
		and not target_4.getValue()="493"
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
