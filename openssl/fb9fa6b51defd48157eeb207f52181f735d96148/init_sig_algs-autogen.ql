/**
 * @name openssl-fb9fa6b51defd48157eeb207f52181f735d96148-init_sig_algs
 * @id cpp/openssl/fb9fa6b51defd48157eeb207f52181f735d96148/init-sig-algs
 * @description openssl-fb9fa6b51defd48157eeb207f52181f735d96148-init_sig_algs CVE-2021-3449
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1137, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="peer_sigalgslen"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1137
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vs_1137) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="tmp"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1137)
}

from Function func, Parameter vs_1137
where
not func_0(vs_1137, func)
and vs_1137.getType().hasName("SSL *")
and func_1(vs_1137)
and vs_1137.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
