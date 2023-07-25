/**
 * @name ffmpeg-3eedf9f716733b3b4c5205726d2c1ca52b3d3d78-get_sot
 * @id cpp/ffmpeg/3eedf9f716733b3b4c5205726d2c1ca52b3d3d78/get-sot
 * @description ffmpeg-3eedf9f716733b3b4c5205726d2c1ca52b3d3d78-libavcodec/j2kdec.c-get_sot CVE-2012-0855
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_424, AddressOfExpr target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="curtileno"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_424
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="numXtiles"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_424
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="numYtiles"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_424
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="curtileno"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_424
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_424, AddressOfExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_424
}

predicate func_2(Parameter vs_424, ExprStmt target_2) {
		target_2.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_2.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_424
		and target_2.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="4"
}

from Function func, Parameter vs_424, AddressOfExpr target_1, ExprStmt target_2
where
not func_0(vs_424, target_1, target_2, func)
and func_1(vs_424, target_1)
and func_2(vs_424, target_2)
and vs_424.getType().hasName("J2kDecoderContext *")
and vs_424.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
