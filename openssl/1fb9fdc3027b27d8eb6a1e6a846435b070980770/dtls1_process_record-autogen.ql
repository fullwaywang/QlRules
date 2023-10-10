/**
 * @name openssl-1fb9fdc3027b27d8eb6a1e6a846435b070980770-dtls1_process_record
 * @id cpp/openssl/1fb9fdc3027b27d8eb6a1e6a846435b070980770/dtls1-process-record
 * @description openssl-1fb9fdc3027b27d8eb6a1e6a846435b070980770-dtls1_process_record CVE-2016-2181
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1276, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("dtls1_record_bitmap_update")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1276
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("DTLS1_BITMAP *")
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vs_1276) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="rlayer"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1276)
}

from Function func, Parameter vs_1276
where
not func_0(vs_1276, func)
and vs_1276.getType().hasName("SSL *")
and func_1(vs_1276)
and vs_1276.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
