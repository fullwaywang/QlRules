import cpp

predicate func_0(Parameter vbuf, Parameter vn, Parameter vformat, Parameter vargs, Variable vretlen, Variable vtruncated, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getType().hasName("int")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_dopr")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getType().hasName("char **")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("size_t *")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vn
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getType().hasName("size_t *")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vretlen
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(AddressOfExpr).getType().hasName("int *")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtruncated
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vformat
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vargs
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getType().hasName("int")
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_1(Parameter vbuf) {
	exists(AddressOfExpr target_1 |
		target_1.getType().hasName("char **")
		and target_1.getOperand().(VariableAccess).getTarget()=vbuf)
}

predicate func_2(Parameter vn) {
	exists(AddressOfExpr target_2 |
		target_2.getType().hasName("size_t *")
		and target_2.getOperand().(VariableAccess).getTarget()=vn)
}

predicate func_3(Variable vretlen) {
	exists(AddressOfExpr target_3 |
		target_3.getType().hasName("size_t *")
		and target_3.getOperand().(VariableAccess).getTarget()=vretlen)
}

predicate func_4(Variable vtruncated) {
	exists(AddressOfExpr target_4 |
		target_4.getType().hasName("int *")
		and target_4.getOperand().(VariableAccess).getTarget()=vtruncated)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="0"
		and target_5.getEnclosingFunction() = func)
}

predicate func_8(Parameter vformat, Parameter vargs, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("_dopr")
		and target_8.getExpr().(FunctionCall).getType().hasName("void")
		and target_8.getExpr().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_8.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_8.getExpr().(FunctionCall).getArgument(3) instanceof AddressOfExpr
		and target_8.getExpr().(FunctionCall).getArgument(4) instanceof AddressOfExpr
		and target_8.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vformat
		and target_8.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vargs
		and target_8.getEnclosingFunction() = func
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

from Function func, Parameter vbuf, Parameter vn, Parameter vformat, Parameter vargs, Variable vretlen, Variable vtruncated
where
not func_0(vbuf, vn, vformat, vargs, vretlen, vtruncated, func)
and func_1(vbuf)
and func_2(vn)
and func_3(vretlen)
and func_4(vtruncated)
and func_5(func)
and func_8(vformat, vargs, func)
and vbuf.getType().hasName("char *")
and vn.getType().hasName("size_t")
and vformat.getType().hasName("const char *")
and vargs.getType().hasName("va_list")
and vretlen.getType().hasName("size_t")
and vtruncated.getType().hasName("int")
and vbuf.getParentScope+() = func
and vn.getParentScope+() = func
and vformat.getParentScope+() = func
and vargs.getParentScope+() = func
and vretlen.getParentScope+() = func
and vtruncated.getParentScope+() = func
select func, vbuf, vn, vformat, vargs, vretlen, vtruncated
