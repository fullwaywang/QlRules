/**
 * @name openssl-1fb9fdc3027b27d8eb6a1e6a846435b070980770-dtls1_get_record
 * @id cpp/openssl/1fb9fdc3027b27d8eb6a1e6a846435b070980770/dtls1-get-record
 * @description openssl-1fb9fdc3027b27d8eb6a1e6a846435b070980770-dtls1_get_record CVE-2016-2181
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1458) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("dtls1_process_record")
		and not target_0.getTarget().hasName("dtls1_process_buffered_records")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vs_1458)
}

predicate func_1(Variable vrr_1462, Variable vbitmap_1465, Parameter vs_1458) {
	exists(NotExpr target_1 |
		target_1.getOperand().(FunctionCall).getTarget().hasName("dtls1_process_record")
		and target_1.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1458
		and target_1.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbitmap_1465
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrr_1462
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="packet_length"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_2(Parameter vs_1458) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("dtls1_process_buffered_records")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vs_1458)
}

predicate func_5(Function func) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand() instanceof FunctionCall
		and target_5.getGreaterOperand().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable vbitmap_1465, Parameter vs_1458) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("dtls1_record_bitmap_update")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1458
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbitmap_1465
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("SSL_in_init")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1458
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("ossl_statem_get_in_handshake")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1458)
}

from Function func, Variable vrr_1462, Variable vbitmap_1465, Parameter vs_1458
where
func_0(vs_1458)
and not func_1(vrr_1462, vbitmap_1465, vs_1458)
and func_2(vs_1458)
and func_5(func)
and func_6(vbitmap_1465, vs_1458)
and vrr_1462.getType().hasName("SSL3_RECORD *")
and vbitmap_1465.getType().hasName("DTLS1_BITMAP *")
and vs_1458.getType().hasName("SSL *")
and vrr_1462.getParentScope+() = func
and vbitmap_1465.getParentScope+() = func
and vs_1458.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
