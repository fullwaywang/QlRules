import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="101"
		and not target_0.getValue()="109"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="106"
		and not target_1.getValue()="114"
		and target_1.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="112"
		and not target_3.getValue()="120"
		and target_3.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="123"
		and not target_5.getValue()="131"
		and target_5.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="129"
		and not target_7.getValue()="137"
		and target_7.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="136"
		and not target_9.getValue()="146"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="137"
		and not target_10.getValue()="147"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(Literal target_11 |
		target_11.getValue()="143"
		and not target_11.getValue()="155"
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(Literal target_12 |
		target_12.getValue()="144"
		and not target_12.getValue()="156"
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Function func) {
	exists(Literal target_13 |
		target_13.getValue()="149"
		and not target_13.getValue()="161"
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Function func) {
	exists(Literal target_14 |
		target_14.getValue()="150"
		and not target_14.getValue()="162"
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Variable vl) {
	exists(LogicalOrExpr target_15 |
		target_15.getType().hasName("int")
		and target_15.getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_15.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getType().hasName("int")
		and target_15.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_ptr")
		and target_15.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_15.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="test/list_test.c"
		and target_15.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="144"
		and target_15.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ossl_list_int_head(&l)"
		and target_15.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("ossl_list_int_head")
		and target_15.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl
		and target_15.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getType().hasName("int")
		and target_15.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_ptr")
		and target_15.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_15.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="test/list_test.c"
		and target_15.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="145"
		and target_15.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ossl_list_int_tail(&l)"
		and target_15.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("ossl_list_int_tail")
		and target_15.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl
		and target_15.getRightOperand().(NotExpr).getType().hasName("int")
		and target_15.getRightOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_int_eq")
		and target_15.getRightOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_15.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="test/list_test.c"
		and target_15.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="146"
		and target_15.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ossl_list_int_head(&l)->n"
		and target_15.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(StringLiteral).getValue()="5"
		and target_15.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="n"
		and target_15.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getType().hasName("int")
		and target_15.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("ossl_list_int_head")
		and target_15.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl
		and target_15.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(5).(Literal).getValue()="5"
		and target_15.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getType().hasName("int")
		and target_15.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_int_eq")
		and target_15.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_15.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="test/list_test.c"
		and target_15.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="147"
		and target_15.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ossl_list_int_tail(&l)->n"
		and target_15.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(StringLiteral).getValue()="5"
		and target_15.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="n"
		and target_15.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("ossl_list_int_tail")
		and target_15.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl
		and target_15.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(5).(Literal).getValue()="5"
		and target_15.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_16(Variable vl) {
	exists(LogicalOrExpr target_16 |
		target_16.getType().hasName("int")
		and target_16.getLeftOperand().(LogicalOrExpr).getType().hasName("int")
		and target_16.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getType().hasName("int")
		and target_16.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_ptr")
		and target_16.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_16.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="test/list_test.c"
		and target_16.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="153"
		and target_16.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ossl_list_int_head(&l)"
		and target_16.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("ossl_list_int_head")
		and target_16.getLeftOperand().(LogicalOrExpr).getLeftOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl
		and target_16.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getType().hasName("int")
		and target_16.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_ptr")
		and target_16.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_16.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="test/list_test.c"
		and target_16.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="154"
		and target_16.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ossl_list_int_tail(&l)"
		and target_16.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("ossl_list_int_tail")
		and target_16.getLeftOperand().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl
		and target_16.getRightOperand().(NotExpr).getType().hasName("int")
		and target_16.getRightOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_int_eq")
		and target_16.getRightOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_16.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="test/list_test.c"
		and target_16.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="155"
		and target_16.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ossl_list_int_head(&l)->n"
		and target_16.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(StringLiteral).getValue()="0"
		and target_16.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="n"
		and target_16.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getType().hasName("int")
		and target_16.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("ossl_list_int_head")
		and target_16.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl
		and target_16.getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_16.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getType().hasName("int")
		and target_16.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_int_eq")
		and target_16.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_16.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="test/list_test.c"
		and target_16.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="156"
		and target_16.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ossl_list_int_tail(&l)->n"
		and target_16.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(3).(StringLiteral).getValue()="0"
		and target_16.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="n"
		and target_16.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("ossl_list_int_tail")
		and target_16.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl
		and target_16.getParent().(LogicalOrExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_16.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Variable vl
where
func_0(func)
and func_1(func)
and func_3(func)
and func_5(func)
and func_7(func)
and func_9(func)
and func_10(func)
and func_11(func)
and func_12(func)
and func_13(func)
and func_14(func)
and not func_15(vl)
and not func_16(vl)
and vl.getType().hasName("OSSL_LIST_int")
and vl.getParentScope+() = func
select func, vl
