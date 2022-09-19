import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="401"
		and not target_0.getValue()="416"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="411"
		and not target_1.getValue()="426"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="425"
		and not target_2.getValue()="440"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vs, Variable vfrag_off, Variable vfrag_len, Variable vmsg_len) {
	exists(LogicalOrExpr target_3 |
		target_3.getType().hasName("int")
		and target_3.getLeftOperand().(GTExpr).getType().hasName("int")
		and target_3.getLeftOperand().(GTExpr).getGreaterOperand().(AddExpr).getType().hasName("unsigned long")
		and target_3.getLeftOperand().(GTExpr).getGreaterOperand().(AddExpr).getLeftOperand().(VariableAccess).getTarget()=vfrag_off
		and target_3.getLeftOperand().(GTExpr).getGreaterOperand().(AddExpr).getRightOperand().(VariableAccess).getTarget()=vfrag_len
		and target_3.getLeftOperand().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vmsg_len
		and target_3.getRightOperand().(GTExpr).getType().hasName("int")
		and target_3.getRightOperand().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vmsg_len
		and target_3.getRightOperand().(GTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("dtls1_max_handshake_message_len")
		and target_3.getRightOperand().(GTExpr).getLesserOperand().(FunctionCall).getType().hasName("unsigned long")
		and target_3.getRightOperand().(GTExpr).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="288"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="152"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="ssl/statem/statem_dtls.c"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="416"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="47")
}

predicate func_4(Variable vfrag_off, Variable vfrag_len, Variable vmsg_len) {
	exists(GTExpr target_4 |
		target_4.getType().hasName("int")
		and target_4.getGreaterOperand().(AddExpr).getType().hasName("unsigned long")
		and target_4.getGreaterOperand().(AddExpr).getLeftOperand().(VariableAccess).getTarget()=vfrag_off
		and target_4.getGreaterOperand().(AddExpr).getRightOperand().(VariableAccess).getTarget()=vfrag_len
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vmsg_len
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="288"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="152"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="ssl/statem/statem_dtls.c"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="47")
}

from Function func, Parameter vs, Variable vfrag_off, Variable vfrag_len, Variable vmsg_len
where
func_0(func)
and func_1(func)
and func_2(func)
and not func_3(vs, vfrag_off, vfrag_len, vmsg_len)
and func_4(vfrag_off, vfrag_len, vmsg_len)
and vs.getType().hasName("SSL *")
and vfrag_off.getType().hasName("size_t")
and vfrag_len.getType().hasName("size_t")
and vmsg_len.getType().hasName("size_t")
and vs.getParentScope+() = func
and vfrag_off.getParentScope+() = func
and vfrag_len.getParentScope+() = func
and vmsg_len.getParentScope+() = func
select func, vs, vfrag_off, vfrag_len, vmsg_len
