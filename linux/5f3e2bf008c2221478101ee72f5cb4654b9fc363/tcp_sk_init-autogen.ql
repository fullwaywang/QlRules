/**
 * @name linux-5f3e2bf008c2221478101ee72f5cb4654b9fc363-tcp_sk_init
 * @id cpp/linux/5f3e2bf008c2221478101ee72f5cb4654b9fc363/tcp_sk_init
 * @description linux-5f3e2bf008c2221478101ee72f5cb4654b9fc363-tcp_sk_init CVE-2019-11479
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vnet_2602, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="sysctl_tcp_min_snd_mss"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ipv4"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnet_2602
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="48"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vnet_2602) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="ipv4"
		and target_1.getQualifier().(VariableAccess).getTarget()=vnet_2602)
}

from Function func, Parameter vnet_2602
where
not func_0(vnet_2602, func)
and vnet_2602.getType().hasName("net *")
and func_1(vnet_2602)
and vnet_2602.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
