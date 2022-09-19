import cpp

predicate func_0(Function func) {
	exists(SwitchCase target_0 |
		target_0.getExpr().(BitwiseOrExpr).getType().hasName("int")
		and target_0.getExpr().(BitwiseOrExpr).getValue()="258"
		and target_0.getExpr().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="2"
		and target_0.getExpr().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="256"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(SwitchCase target_1 |
		target_1.getExpr().(BitwiseOrExpr).getType().hasName("int")
		and target_1.getExpr().(BitwiseOrExpr).getValue()="266"
		and target_1.getExpr().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="10"
		and target_1.getExpr().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="256"
		and target_1.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_1(func)
select func
