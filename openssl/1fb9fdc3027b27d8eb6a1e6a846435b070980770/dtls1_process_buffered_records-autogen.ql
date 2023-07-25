/**
 * @name openssl-1fb9fdc3027b27d8eb6a1e6a846435b070980770-dtls1_process_buffered_records
 * @id cpp/openssl/1fb9fdc3027b27d8eb6a1e6a846435b070980770/dtls1-process-buffered-records
 * @description openssl-1fb9fdc3027b27d8eb6a1e6a846435b070980770-dtls1_process_buffered_records CVE-2016-2181
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getStmt(2)=target_0)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_1)
}

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof IntType
		and func.getEntryPoint().(BlockStmt).getStmt(4)=target_2)
}

predicate func_3(Function func) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getStmt(5)=target_3)
}

predicate func_4(Parameter vs_229, Variable vitem_231) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("SSL3_RECORD *")
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="rrec"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_229
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vitem_231)
}

predicate func_5(Parameter vs_229) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("DTLS1_BITMAP *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dtls1_get_bitmap")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_229
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("SSL3_RECORD *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned int"))
}

predicate func_8(Parameter vs_229) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dtls1_record_replay_check")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_229
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("DTLS1_BITMAP *"))
}

predicate func_15(Parameter vs_229) {
	exists(ContinueStmt target_15 |
		target_15.toString() = "continue;"
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("dtls1_process_record")
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_229
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("DTLS1_BITMAP *"))
}

predicate func_16(Function func) {
	exists(IfStmt target_16 |
		target_16.getCondition() instanceof RelationalOperation
		and target_16.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_16.getEnclosingFunction() = func)
}

predicate func_18(Function func) {
	exists(LabelStmt target_18 |
		target_18.toString() = "label ...:"
		and target_18.getEnclosingFunction() = func)
}

predicate func_19(Parameter vs_229) {
	exists(ReturnStmt target_19 |
		target_19.getExpr().(Literal).getValue()="0"
		and target_19.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("dtls1_process_record")
		and target_19.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_229)
}

predicate func_20(Parameter vs_229) {
	exists(RelationalOperation target_20 |
		 (target_20 instanceof GTExpr or target_20 instanceof LTExpr)
		and target_20.getLesserOperand().(FunctionCall).getTarget().hasName("dtls1_buffer_record")
		and target_20.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_229
		and target_20.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="processed_rcds"
		and target_20.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="d"
		and target_20.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_20.getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_229
		and target_20.getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="seq_num"
		and target_20.getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="rrec"
		and target_20.getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_20.getLesserOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_229
		and target_20.getGreaterOperand().(Literal).getValue()="0"
		and target_20.getParent().(IfStmt).getThen().(ReturnStmt).getExpr() instanceof UnaryMinusExpr)
}

predicate func_22(Function func) {
	exists(Literal target_22 |
		target_22.getValue()="1"
		and target_22.getEnclosingFunction() = func)
}

predicate func_23(Function func) {
	exists(UnaryMinusExpr target_23 |
		target_23.getValue()="-1"
		and target_23.getEnclosingFunction() = func)
}

predicate func_24(Parameter vs_229) {
	exists(ValueFieldAccess target_24 |
		target_24.getTarget().getName()="d"
		and target_24.getQualifier().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_24.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_229)
}

predicate func_26(Parameter vs_229) {
	exists(NotExpr target_26 |
		target_26.getOperand().(FunctionCall).getTarget().hasName("dtls1_process_record")
		and target_26.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_229
		and target_26.getParent().(IfStmt).getThen() instanceof ReturnStmt)
}

from Function func, Parameter vs_229, Variable vitem_231
where
not func_0(func)
and not func_1(func)
and not func_2(func)
and not func_3(func)
and not func_4(vs_229, vitem_231)
and not func_5(vs_229)
and not func_8(vs_229)
and not func_15(vs_229)
and not func_16(func)
and not func_18(func)
and func_19(vs_229)
and func_20(vs_229)
and func_22(func)
and func_23(func)
and vs_229.getType().hasName("SSL *")
and func_24(vs_229)
and func_26(vs_229)
and vitem_231.getType().hasName("pitem *")
and vs_229.getParentScope+() = func
and vitem_231.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
