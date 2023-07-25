/**
 * @name ffmpeg-58bb9d3a3a6ede1c6cfb82bf671a5f138e6b2144-filter_frame
 * @id cpp/ffmpeg/58bb9d3a3a6ede1c6cfb82bf671a5f138e6b2144/filter-frame
 * @description ffmpeg-58bb9d3a3a6ede1c6cfb82bf671a5f138e6b2144-libavfilter/af_tremolo.c-filter_frame CVE-2020-22026
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinlink_45, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="sample_rate"
		and target_0.getQualifier().(VariableAccess).getTarget()=vinlink_45
}

predicate func_1(Variable vs_49, VariableAccess target_1) {
		target_1.getTarget()=vs_49
}

predicate func_2(Variable vs_49, Parameter vinlink_45, ExprStmt target_3, DivExpr target_2) {
		target_2.getLeftOperand().(PointerFieldAccess).getTarget().getName()="sample_rate"
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinlink_45
		and target_2.getRightOperand().(PointerFieldAccess).getTarget().getName()="freq"
		and target_2.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_49
		and target_2.getParent().(GEExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="index"
		and target_2.getParent().(GEExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_49
		and target_2.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_3
}

predicate func_3(Variable vs_49, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="index"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_49
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vs_49, Parameter vinlink_45, PointerFieldAccess target_0, VariableAccess target_1, DivExpr target_2, ExprStmt target_3
where
func_0(vinlink_45, target_0)
and func_1(vs_49, target_1)
and func_2(vs_49, vinlink_45, target_3, target_2)
and func_3(vs_49, target_3)
and vs_49.getType().hasName("TremoloContext *")
and vinlink_45.getType().hasName("AVFilterLink *")
and vs_49.getParentScope+() = func
and vinlink_45.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
