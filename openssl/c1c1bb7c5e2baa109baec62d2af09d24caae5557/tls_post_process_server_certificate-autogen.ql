/**
 * @name openssl-c1c1bb7c5e2baa109baec62d2af09d24caae5557-tls_post_process_server_certificate
 * @id cpp/openssl/c1c1bb7c5e2baa109baec62d2af09d24caae5557/tls-post-process-server-certificate
 * @description openssl-c1c1bb7c5e2baa109baec62d2af09d24caae5557-tls_post_process_server_certificate CVE-2021-4044
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_1860, Parameter vs_1854) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vi_1860
		and target_0.getAnOperand() instanceof Literal
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="verify_mode"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1854
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vs_1854
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(FunctionCall).getTarget().hasName("ssl_x509err2alert")
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(Literal).getValue()="134"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(3).(Literal).getValue()="0")
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="0"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vi_1860, Parameter vs_1854) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vi_1860
		and target_3.getGreaterOperand() instanceof Literal
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="verify_mode"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1854
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vs_1854
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(FunctionCall).getTarget().hasName("ssl_x509err2alert")
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(Literal).getValue()="134"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(3).(Literal).getValue()="0")
}

from Function func, Variable vi_1860, Parameter vs_1854
where
not func_0(vi_1860, vs_1854)
and func_2(func)
and func_3(vi_1860, vs_1854)
and vi_1860.getType().hasName("int")
and vs_1854.getType().hasName("SSL *")
and vi_1860.getParentScope+() = func
and vs_1854.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
