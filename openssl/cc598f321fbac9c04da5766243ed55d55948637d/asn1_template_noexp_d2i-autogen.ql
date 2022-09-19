import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="624"
		and not target_0.getValue()="627"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="643"
		and not target_1.getValue()="646"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="655"
		and not target_2.getValue()="658"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="666"
		and not target_3.getValue()="669"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="671"
		and not target_4.getValue()="674"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="676"
		and not target_5.getValue()="679"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="685"
		and not target_6.getValue()="688"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="694"
		and not target_7.getValue()="697"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="0"
		and not target_8.getValue()="1"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Parameter vtt) {
	exists(BitwiseAndExpr target_9 |
		target_9.getType().hasName("unsigned long")
		and target_9.getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_9.getLeftOperand().(PointerFieldAccess).getType().hasName("unsigned long")
		and target_9.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt
		and target_9.getRightOperand().(LShiftExpr).getType().hasName("int")
		and target_9.getRightOperand().(LShiftExpr).getValue()="1024"
		and target_9.getRightOperand().(LShiftExpr).getLeftOperand().(Literal).getValue()="1"
		and target_9.getRightOperand().(LShiftExpr).getRightOperand().(Literal).getValue()="10")
}

from Function func, Parameter vtt
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
and not func_9(vtt)
and vtt.getType().hasName("const ASN1_TEMPLATE *")
and vtt.getParentScope+() = func
select func, vtt
