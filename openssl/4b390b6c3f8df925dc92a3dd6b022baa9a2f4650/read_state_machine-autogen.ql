import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="561"
		and not target_0.getValue()="572"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="611"
		and not target_1.getValue()="622"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vs) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalAndExpr).getType().hasName("int")
		and target_2.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getType().hasName("int")
		and target_2.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(NotExpr).getType().hasName("int")
		and target_2.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="enc_flags"
		and target_2.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ssl3_enc"
		and target_2.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="method"
		and target_2.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_2.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8"
		and target_2.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(GTExpr).getType().hasName("int")
		and target_2.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(GTExpr).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="message_size"
		and target_2.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(GTExpr).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_2.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(GTExpr).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_2.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(GTExpr).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_2.getCondition().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(GTExpr).getLesserOperand().(Literal).getValue()="0"
		and target_2.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getType().hasName("int")
		and target_2.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BUF_MEM_grow_clean")
		and target_2.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getType().hasName("size_t")
		and target_2.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="init_buf"
		and target_2.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_2.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="message_size"
		and target_2.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_2.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_2.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_2.getCondition().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddExpr).getRightOperand().(Literal).getValue()="4"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl3_send_alert")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getType().hasName("int")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="80"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="387"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="7"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="ssl/statem/statem.c"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="552")
}

predicate func_5(Parameter vs, Variable vlen, Variable vpkt) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("ssl3_send_alert")
		and target_5.getExpr().(FunctionCall).getType().hasName("int")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_5.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="80"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("PACKET_buf_init")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpkt
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="init_msg"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen)
}

predicate func_6(Parameter vs, Variable vlen, Variable vpkt) {
	exists(ReturnStmt target_6 |
		target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("PACKET_buf_init")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpkt
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="init_msg"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen)
}

from Function func, Parameter vs, Variable vlen, Variable vpkt
where
func_0(func)
and func_1(func)
and not func_2(vs)
and func_5(vs, vlen, vpkt)
and func_6(vs, vlen, vpkt)
and vs.getType().hasName("SSL *")
and vlen.getType().hasName("unsigned long")
and vpkt.getType().hasName("PACKET")
and vs.getParentScope+() = func
and vlen.getParentScope+() = func
and vpkt.getParentScope+() = func
select func, vs, vlen, vpkt
