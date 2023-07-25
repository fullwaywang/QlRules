/**
 * @name openssl-76343947ada960b6269090638f5391068daee88d-tls1_set_server_sigalgs
 * @id cpp/openssl/76343947ada960b6269090638f5391068daee88d/tls1-set-server-sigalgs
 * @description openssl-76343947ada960b6269090638f5391068daee88d-tls1_set_server_sigalgs CVE-2015-0291
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_2962) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="shared_sigalgslen"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cert"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2962
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="shared_sigalgs"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cert"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2962)
}

predicate func_1(Parameter vs_2962) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="shared_sigalgs"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cert"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2962
		and target_1.getRValue().(Literal).getValue()="0")
}

from Function func, Parameter vs_2962
where
not func_0(vs_2962)
and vs_2962.getType().hasName("SSL *")
and func_1(vs_2962)
and vs_2962.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
