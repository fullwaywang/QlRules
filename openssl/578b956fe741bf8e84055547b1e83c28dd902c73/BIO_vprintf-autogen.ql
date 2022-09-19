import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="770"
		and not target_0.getValue()="810"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vformat, Parameter vargs, Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("_dopr")
		and not target_1.getTarget().hasName("CRYPTO_free")
		and target_1.getType().hasName("void")
		and target_1.getArgument(0) instanceof AddressOfExpr
		and target_1.getArgument(1) instanceof AddressOfExpr
		and target_1.getArgument(2) instanceof AddressOfExpr
		and target_1.getArgument(3) instanceof AddressOfExpr
		and target_1.getArgument(4) instanceof AddressOfExpr
		and target_1.getArgument(5).(VariableAccess).getTarget()=vformat
		and target_1.getArgument(6).(VariableAccess).getTarget()=vargs
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vformat, Parameter vargs, Variable vretlen, Variable vhugebufp, Variable vhugebufsize, Variable vdynbuf, Variable vignored, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getType().hasName("int")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_dopr")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getType().hasName("char **")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vhugebufp
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getType().hasName("char **")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdynbuf
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("size_t *")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vhugebufsize
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getType().hasName("size_t *")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vretlen
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(AddressOfExpr).getType().hasName("int *")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vignored
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vformat
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vargs
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdynbuf
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getType().hasName("int")
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_4(Variable vhugebufp) {
	exists(AddressOfExpr target_4 |
		target_4.getType().hasName("char **")
		and target_4.getOperand().(VariableAccess).getTarget()=vhugebufp)
}

predicate func_5(Variable vdynbuf) {
	exists(AddressOfExpr target_5 |
		target_5.getType().hasName("char **")
		and target_5.getOperand().(VariableAccess).getTarget()=vdynbuf)
}

predicate func_6(Variable vhugebufsize) {
	exists(AddressOfExpr target_6 |
		target_6.getType().hasName("size_t *")
		and target_6.getOperand().(VariableAccess).getTarget()=vhugebufsize)
}

predicate func_7(Variable vretlen) {
	exists(AddressOfExpr target_7 |
		target_7.getType().hasName("size_t *")
		and target_7.getOperand().(VariableAccess).getTarget()=vretlen)
}

predicate func_8(Variable vignored) {
	exists(AddressOfExpr target_8 |
		target_8.getType().hasName("int *")
		and target_8.getOperand().(VariableAccess).getTarget()=vignored)
}

from Function func, Parameter vformat, Parameter vargs, Variable vretlen, Variable vhugebufp, Variable vhugebufsize, Variable vdynbuf, Variable vignored
where
func_0(func)
and func_1(vformat, vargs, func)
and not func_2(vformat, vargs, vretlen, vhugebufp, vhugebufsize, vdynbuf, vignored, func)
and func_4(vhugebufp)
and func_5(vdynbuf)
and func_6(vhugebufsize)
and func_7(vretlen)
and func_8(vignored)
and vformat.getType().hasName("const char *")
and vargs.getType().hasName("va_list")
and vretlen.getType().hasName("size_t")
and vhugebufp.getType().hasName("char *")
and vhugebufsize.getType().hasName("size_t")
and vdynbuf.getType().hasName("char *")
and vignored.getType().hasName("int")
and vformat.getParentScope+() = func
and vargs.getParentScope+() = func
and vretlen.getParentScope+() = func
and vhugebufp.getParentScope+() = func
and vhugebufsize.getParentScope+() = func
and vdynbuf.getParentScope+() = func
and vignored.getParentScope+() = func
select func, vformat, vargs, vretlen, vhugebufp, vhugebufsize, vdynbuf, vignored
