/**
 * @name ffmpeg-2a05c8f813de6f2278827734bf8102291e7484aa-http_proxy_open
 * @id cpp/ffmpeg/2a05c8f813de6f2278827734bf8102291e7484aa/http-proxy-open
 * @description ffmpeg-2a05c8f813de6f2278827734bf8102291e7484aa-libavformat/http.c-http_proxy_open CVE-2016-10190
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_1575, ExprStmt target_3, ExprStmt target_4) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="filesize"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1575
		and target_0.getRValue().(Literal).getValue()="18446744073709551615"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_1575, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="filesize"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_1575
		and target_1.getParent().(AssignExpr).getLValue() = target_1
		and target_1.getParent().(AssignExpr).getRValue() instanceof UnaryMinusExpr
}

predicate func_2(Variable vs_1575, AssignExpr target_2) {
		target_2.getLValue().(PointerFieldAccess).getTarget().getName()="filesize"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1575
		and target_2.getRValue().(UnaryMinusExpr).getValue()="-1"
}

predicate func_3(Variable vs_1575, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="line_count"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1575
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_4(Variable vs_1575, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="auth_type"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="proxy_auth_state"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1575
}

from Function func, Variable vs_1575, PointerFieldAccess target_1, AssignExpr target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vs_1575, target_3, target_4)
and func_1(vs_1575, target_1)
and func_2(vs_1575, target_2)
and func_3(vs_1575, target_3)
and func_4(vs_1575, target_4)
and vs_1575.getType().hasName("HTTPContext *")
and vs_1575.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
