/**
 * @name ffmpeg-2a05c8f813de6f2278827734bf8102291e7484aa-http_connect
 * @id cpp/ffmpeg/2a05c8f813de6f2278827734bf8102291e7484aa/http-connect
 * @description ffmpeg-2a05c8f813de6f2278827734bf8102291e7484aa-libavformat/http.c-http_connect CVE-2016-10190
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="Range: bytes=%ld-"
		and not target_1.getValue()="Range: bytes=%lu-"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vs_1005, ExprStmt target_5, ExprStmt target_6) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(PointerFieldAccess).getTarget().getName()="filesize"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1005
		and target_2.getRValue().(Literal).getValue()="18446744073709551615"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vs_1005, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="filesize"
		and target_3.getQualifier().(VariableAccess).getTarget()=vs_1005
		and target_3.getParent().(AssignExpr).getLValue() = target_3
		and target_3.getParent().(AssignExpr).getRValue() instanceof UnaryMinusExpr
}

predicate func_4(Variable vs_1005, AssignExpr target_4) {
		target_4.getLValue().(PointerFieldAccess).getTarget().getName()="filesize"
		and target_4.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1005
		and target_4.getRValue().(UnaryMinusExpr).getValue()="-1"
}

predicate func_5(Variable vs_1005, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="icy_data_read"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1005
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_6(Variable vs_1005, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="willclose"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1005
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vs_1005, StringLiteral target_1, PointerFieldAccess target_3, AssignExpr target_4, ExprStmt target_5, ExprStmt target_6
where
func_1(func, target_1)
and not func_2(vs_1005, target_5, target_6)
and func_3(vs_1005, target_3)
and func_4(vs_1005, target_4)
and func_5(vs_1005, target_5)
and func_6(vs_1005, target_6)
and vs_1005.getType().hasName("HTTPContext *")
and vs_1005.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
