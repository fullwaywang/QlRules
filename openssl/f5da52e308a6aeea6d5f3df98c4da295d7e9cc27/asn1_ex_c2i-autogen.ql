import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="935"
		and not target_0.getValue()="933"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="940"
		and not target_1.getValue()="938"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="947"
		and not target_2.getValue()="945"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="964"
		and not target_3.getValue()="962"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(SwitchCase target_4 |
		target_4.getExpr().(BitwiseOrExpr).getType().hasName("int")
		and target_4.getExpr().(BitwiseOrExpr).getValue()="258"
		and target_4.getExpr().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="2"
		and target_4.getExpr().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="256"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(SwitchCase target_5 |
		target_5.getExpr().(BitwiseOrExpr).getType().hasName("int")
		and target_5.getExpr().(BitwiseOrExpr).getValue()="266"
		and target_5.getExpr().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="10"
		and target_5.getExpr().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="256"
		and target_5.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_5(func)
select func
