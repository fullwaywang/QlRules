import cpp

predicate func_0(Parameter vsize, Variable vtarget_info_len, Variable vtarget_info_offset, Parameter vdata) {
	exists(LogicalOrExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLeftOperand().(GEExpr).getType().hasName("int")
		and target_0.getLeftOperand().(GEExpr).getGreaterOperand().(VariableAccess).getTarget()=vtarget_info_offset
		and target_0.getLeftOperand().(GEExpr).getLesserOperand().(VariableAccess).getTarget()=vsize
		and target_0.getRightOperand().(GTExpr).getType().hasName("int")
		and target_0.getRightOperand().(GTExpr).getGreaterOperand().(AddExpr).getType().hasName("unsigned int")
		and target_0.getRightOperand().(GTExpr).getGreaterOperand().(AddExpr).getLeftOperand().(VariableAccess).getTarget()=vtarget_info_offset
		and target_0.getRightOperand().(GTExpr).getGreaterOperand().(AddExpr).getRightOperand().(VariableAccess).getTarget()=vtarget_info_len
		and target_0.getRightOperand().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vsize
		and target_0.getParent().(LogicalOrExpr).getRightOperand().(LTExpr).getType().hasName("int")
		and target_0.getParent().(LogicalOrExpr).getRightOperand().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vtarget_info_offset
		and target_0.getParent().(LogicalOrExpr).getRightOperand().(LTExpr).getGreaterOperand().(Literal).getValue()="48"
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_infof")
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="NTLM handshake failure (bad type-2 message). Target Info Offset Len is set incorrect by the peer\n")
}

from Function func, Parameter vsize, Variable vtarget_info_len, Variable vtarget_info_offset, Parameter vdata
where
not func_0(vsize, vtarget_info_len, vtarget_info_offset, vdata)
and vsize.getType().hasName("size_t")
and vtarget_info_len.getType().hasName("unsigned short")
and vtarget_info_offset.getType().hasName("unsigned int")
and vdata.getType().hasName("Curl_easy *")
and vsize.getParentScope+() = func
and vtarget_info_len.getParentScope+() = func
and vtarget_info_offset.getParentScope+() = func
and vdata.getParentScope+() = func
select func, vsize, vtarget_info_len, vtarget_info_offset, vdata
