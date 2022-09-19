import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("SSL3_RECORD *")
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("DTLS1_BITMAP *")
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Function func) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("unsigned int")
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Function func) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("int")
		and target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Parameter vs, Variable vitem) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getType().hasName("SSL3_RECORD *")
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="rrec"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getType().hasName("SSL3_RECORD[32]")
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getType().hasName("RECORD_LAYER *")
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vitem)
}

predicate func_6(Parameter vs) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getType().hasName("DTLS1_BITMAP *")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dtls1_get_bitmap")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getType().hasName("DTLS1_BITMAP *")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getType().hasName("unsigned int *"))
}

predicate func_9(Parameter vs) {
	exists(BlockStmt target_9 |
		target_9.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("int")
		and target_9.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dtls1_record_replay_check")
		and target_9.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getType().hasName("int")
		and target_9.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs)
}

predicate func_15(Parameter vs) {
	exists(IfStmt target_15 |
		target_15.getCondition().(LTExpr).getType().hasName("int")
		and target_15.getCondition().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("dtls1_buffer_record")
		and target_15.getCondition().(LTExpr).getLesserOperand().(FunctionCall).getType().hasName("int")
		and target_15.getCondition().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_15.getCondition().(LTExpr).getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getType().hasName("record_pqueue *")
		and target_15.getCondition().(LTExpr).getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="processed_rcds"
		and target_15.getCondition().(LTExpr).getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_15.getCondition().(LTExpr).getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_15.getCondition().(LTExpr).getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_15.getCondition().(LTExpr).getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="seq_num"
		and target_15.getCondition().(LTExpr).getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getType().hasName("unsigned char[8]")
		and target_15.getCondition().(LTExpr).getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="rrec"
		and target_15.getCondition().(LTExpr).getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_15.getCondition().(LTExpr).getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_15.getCondition().(LTExpr).getGreaterOperand().(Literal).getValue()="0"
		and target_15.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_17(Parameter vs) {
	exists(ReturnStmt target_17 |
		target_17.getExpr().(Literal).getValue()="0"
		and target_17.getParent().(IfStmt).getCondition().(NotExpr).getType().hasName("int")
		and target_17.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("dtls1_process_record")
		and target_17.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getType().hasName("int")
		and target_17.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs)
}

predicate func_18(Parameter vs) {
	exists(LTExpr target_18 |
		target_18.getType().hasName("int")
		and target_18.getLesserOperand().(FunctionCall).getTarget().hasName("dtls1_buffer_record")
		and target_18.getLesserOperand().(FunctionCall).getType().hasName("int")
		and target_18.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs
		and target_18.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getType().hasName("record_pqueue *")
		and target_18.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="processed_rcds"
		and target_18.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getType().hasName("record_pqueue")
		and target_18.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_18.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_18.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_18.getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="seq_num"
		and target_18.getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getType().hasName("unsigned char[8]")
		and target_18.getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="rrec"
		and target_18.getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getType().hasName("SSL3_RECORD[32]")
		and target_18.getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_18.getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_18.getGreaterOperand().(Literal).getValue()="0"
		and target_18.getParent().(IfStmt).getThen().(ReturnStmt).getExpr() instanceof UnaryMinusExpr)
}

predicate func_21(Function func) {
	exists(UnaryMinusExpr target_21 |
		target_21.getType().hasName("int")
		and target_21.getValue()="-1"
		and target_21.getOperand() instanceof Literal
		and target_21.getEnclosingFunction() = func)
}

from Function func, Parameter vs, Variable vitem
where
func_0(func)
and not func_1(func)
and not func_2(func)
and not func_3(func)
and not func_4(func)
and not func_5(vs, vitem)
and not func_6(vs)
and not func_9(vs)
and not func_15(vs)
and func_17(vs)
and func_18(vs)
and func_21(func)
and vs.getType().hasName("SSL *")
and vitem.getType().hasName("pitem *")
and vs.getParentScope+() = func
and vitem.getParentScope+() = func
select func, vs, vitem
