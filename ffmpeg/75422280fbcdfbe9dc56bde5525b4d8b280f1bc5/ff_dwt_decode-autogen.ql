/**
 * @name ffmpeg-75422280fbcdfbe9dc56bde5525b4d8b280f1bc5-ff_dwt_decode
 * @id cpp/ffmpeg/75422280fbcdfbe9dc56bde5525b4d8b280f1bc5/ff-dwt-decode
 * @description ffmpeg-75422280fbcdfbe9dc56bde5525b4d8b280f1bc5-libavcodec/jpeg2000dwt.c-ff_dwt_decode CVE-2015-8662
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_596, SwitchStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ndeclevels"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_596
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(0)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(0).getFollowingStmt()=target_0)
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_596, SwitchStmt target_1) {
		target_1.getExpr().(PointerFieldAccess).getTarget().getName()="type"
		and target_1.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_596
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dwt_decode97_float")
		and target_1.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_596
		and target_1.getStmt().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
		and target_1.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dwt_decode97_int")
		and target_1.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_596
}

from Function func, Parameter vs_596, SwitchStmt target_1
where
not func_0(vs_596, target_1, func)
and func_1(vs_596, target_1)
and vs_596.getType().hasName("DWTContext *")
and vs_596.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
