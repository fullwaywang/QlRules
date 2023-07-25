/**
 * @name varnish-fcf5722af75fdbf58dd425dd68d0beaa49bab4f4-http_init_hdr
 * @id cpp/varnish/fcf5722af75fdbf58dd425dd68d0beaa49bab4f4/http-init-hdr
 * @description varnish-fcf5722af75fdbf58dd425dd68d0beaa49bab4f4-bin/varnishd/cache/cache_http.c-http_init_hdr CVE-2022-45059
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vflg_165, Variable vf_167, VariableAccess target_2, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flag"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_167
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vflg_165
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_1(Parameter vflg_165, Function func, IfStmt target_1) {
		target_1.getCondition().(VariableAccess).getTarget()=vflg_165
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(1).(DoStmt).getCondition() instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vflg_165, VariableAccess target_2) {
		target_2.getTarget()=vflg_165
}

from Function func, Parameter vflg_165, Variable vf_167, ExprStmt target_0, IfStmt target_1, VariableAccess target_2
where
func_0(vflg_165, vf_167, target_2, target_0)
and func_1(vflg_165, func, target_1)
and func_2(vflg_165, target_2)
and vflg_165.getType().hasName("int")
and vf_167.getType().hasName("http_hdrflg *")
and vflg_165.getParentScope+() = func
and vf_167.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
