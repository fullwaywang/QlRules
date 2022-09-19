import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="597"
		and not target_0.getValue()="604"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="598"
		and not target_1.getValue()="605"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="599"
		and not target_2.getValue()="606"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="603"
		and not target_3.getValue()="610"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="604"
		and not target_4.getValue()="611"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="616"
		and not target_5.getValue()="623"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="617"
		and not target_6.getValue()="624"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="627"
		and not target_7.getValue()="634"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="628"
		and not target_8.getValue()="635"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="629"
		and not target_9.getValue()="636"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="634"
		and not target_10.getValue()="641"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(Literal target_11 |
		target_11.getValue()="640"
		and not target_11.getValue()="647"
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(Literal target_12 |
		target_12.getValue()="646"
		and not target_12.getValue()="653"
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Function func) {
	exists(Literal target_13 |
		target_13.getValue()="652"
		and not target_13.getValue()="659"
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Function func) {
	exists(Literal target_14 |
		target_14.getValue()="653"
		and not target_14.getValue()="660"
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Function func) {
	exists(Literal target_15 |
		target_15.getValue()="657"
		and not target_15.getValue()="664"
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Function func) {
	exists(Literal target_16 |
		target_16.getValue()="658"
		and not target_16.getValue()="665"
		and target_16.getEnclosingFunction() = func)
}

predicate func_17(Function func) {
	exists(Literal target_17 |
		target_17.getValue()="662"
		and not target_17.getValue()="669"
		and target_17.getEnclosingFunction() = func)
}

predicate func_18(Function func) {
	exists(Literal target_18 |
		target_18.getValue()="663"
		and not target_18.getValue()="670"
		and target_18.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_5(func)
and func_6(func)
and func_7(func)
and func_8(func)
and func_9(func)
and func_10(func)
and func_11(func)
and func_12(func)
and func_13(func)
and func_14(func)
and func_15(func)
and func_16(func)
and func_17(func)
and func_18(func)
select func
