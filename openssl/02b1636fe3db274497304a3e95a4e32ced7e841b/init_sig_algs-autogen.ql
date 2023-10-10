/**
 * @name openssl-02b1636fe3db274497304a3e95a4e32ced7e841b-init_sig_algs
 * @id cpp/openssl/02b1636fe3db274497304a3e95a4e32ced7e841b/init-sig-algs
 * @description openssl-02b1636fe3db274497304a3e95a4e32ced7e841b-init_sig_algs CVE-2021-3449
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1112, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="peer_sigalgslen"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="tmp"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1112
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vs_1112) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="tmp"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1112)
}

from Function func, Parameter vs_1112
where
not func_0(vs_1112, func)
and vs_1112.getType().hasName("SSL *")
and func_1(vs_1112)
and vs_1112.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
