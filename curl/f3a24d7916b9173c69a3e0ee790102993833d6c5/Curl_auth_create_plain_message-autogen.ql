import cpp

predicate func_1(Function func) {
	exists(DivExpr target_1 |
		target_1.getType().hasName("unsigned long")
		and target_1.getValue()="9223372036854775807"
		and target_1.getLeftOperand().(Literal).getValue()="18446744073709551615"
		and target_1.getRightOperand().(Literal).getValue()="2"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(DivExpr target_2 |
		target_2.getType().hasName("unsigned long")
		and target_2.getValue()="4611686018427387903"
		and target_2.getLeftOperand().(Literal).getValue()="18446744073709551615"
		and target_2.getRightOperand().(Literal).getValue()="4"
		and target_2.getEnclosingFunction() = func)
}

from Function func
where
func_1(func)
and not func_2(func)
select func
