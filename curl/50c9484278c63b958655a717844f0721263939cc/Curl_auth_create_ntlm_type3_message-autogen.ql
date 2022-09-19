import cpp

predicate func_0(Variable vsize, Variable vntlmbuf, Variable vntresplen) {
	exists(GTExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getGreaterOperand().(AddExpr).getType().hasName("unsigned long")
		and target_0.getGreaterOperand().(AddExpr).getLeftOperand().(VariableAccess).getTarget()=vntresplen
		and target_0.getGreaterOperand().(AddExpr).getRightOperand().(VariableAccess).getTarget()=vsize
		and target_0.getLesserOperand().(SizeofExprOperator).getType().hasName("unsigned long")
		and target_0.getLesserOperand().(SizeofExprOperator).getValue()="1024"
		and target_0.getLesserOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vntlmbuf)
}

predicate func_1(Parameter vdata) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_1.getExpr().(FunctionCall).getType().hasName("void")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="incoming NTLM message too big")
}

predicate func_4(Function func) {
	exists(DoStmt target_4 |
		target_4.getCondition().(Literal).getValue()="0"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vsize, Variable vntlmbuf, Variable vntresplen, Variable vptr_ntresp) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_5.getExpr().(FunctionCall).getType().hasName("void *")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getType().hasName("unsigned char *")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getType().hasName("unsigned char")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vntlmbuf
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vsize
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vptr_ntresp
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vntresplen)
}

predicate func_6(Variable vsize, Variable vntresplen) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignAddExpr).getType().hasName("size_t")
		and target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vsize
		and target_6.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vntresplen)
}

predicate func_10(Variable vsize, Variable vntresplen) {
	exists(LTExpr target_10 |
		target_10.getType().hasName("int")
		and target_10.getLesserOperand().(VariableAccess).getTarget()=vsize
		and target_10.getGreaterOperand().(SubExpr).getType().hasName("unsigned int")
		and target_10.getGreaterOperand().(SubExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_10.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vntresplen)
}

from Function func, Parameter vdata, Variable vsize, Variable vntlmbuf, Variable vntresplen, Variable vptr_ntresp
where
not func_0(vsize, vntlmbuf, vntresplen)
and not func_1(vdata)
and func_4(func)
and func_5(vsize, vntlmbuf, vntresplen, vptr_ntresp)
and func_6(vsize, vntresplen)
and func_10(vsize, vntresplen)
and vdata.getType().hasName("Curl_easy *")
and vsize.getType().hasName("size_t")
and vntlmbuf.getType().hasName("unsigned char[1024]")
and vntresplen.getType().hasName("unsigned int")
and vptr_ntresp.getType().hasName("unsigned char *")
and vdata.getParentScope+() = func
and vsize.getParentScope+() = func
and vntlmbuf.getParentScope+() = func
and vntresplen.getParentScope+() = func
and vptr_ntresp.getParentScope+() = func
select func, vdata, vsize, vntlmbuf, vntresplen, vptr_ntresp
