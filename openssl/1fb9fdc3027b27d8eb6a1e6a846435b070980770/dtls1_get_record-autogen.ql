import cpp

predicate func_0(Parameter vs) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("dtls1_process_record")
		and not target_0.getTarget().hasName("dtls1_process_buffered_records")
		and target_0.getType().hasName("int")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vs)
}

predicate func_1(Variable vrr, Variable vbitmap, Parameter vs) {
	exists(NotExpr target_1 |
		target_1.getType().hasName("int")
		and target_1.getOperand().(FunctionCall).getTarget().hasName("dtls1_process_record")
		and target_1.getOperand().(FunctionCall).getType().hasName("int")
		and target_1.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_1.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbitmap
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="packet_length"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_2(Parameter vs) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("dtls1_process_buffered_records")
		and target_2.getType().hasName("int")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vs)
}

predicate func_5(Function func) {
	exists(LTExpr target_5 |
		target_5.getType().hasName("int")
		and target_5.getLesserOperand() instanceof FunctionCall
		and target_5.getGreaterOperand().(Literal).getValue()="0"
		and target_5.getEnclosingFunction() = func
		and target_5.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getType().hasName("int")
		and target_5.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_5.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

predicate func_6(Variable vbitmap, Parameter vs) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("dtls1_record_bitmap_update")
		and target_6.getExpr().(FunctionCall).getType().hasName("void")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbitmap
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getType().hasName("int")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(FunctionCall).getTarget().hasName("SSL_in_init")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getRightOperand().(FunctionCall).getTarget().hasName("ossl_statem_get_in_handshake")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs)
}

from Function func, Variable vrr, Variable vbitmap, Parameter vs
where
func_0(vs)
and not func_1(vrr, vbitmap, vs)
and func_2(vs)
and func_5(func)
and func_6(vbitmap, vs)
and vrr.getType().hasName("SSL3_RECORD *")
and vbitmap.getType().hasName("DTLS1_BITMAP *")
and vs.getType().hasName("SSL *")
and vrr.getParentScope+() = func
and vbitmap.getParentScope+() = func
and vs.getParentScope+() = func
select func, vrr, vbitmap, vs
