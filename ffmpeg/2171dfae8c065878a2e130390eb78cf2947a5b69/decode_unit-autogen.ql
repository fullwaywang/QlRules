/**
 * @name ffmpeg-2171dfae8c065878a2e130390eb78cf2947a5b69-decode_unit
 * @id cpp/ffmpeg/2171dfae8c065878a2e130390eb78cf2947a5b69/decode-unit
 * @description ffmpeg-2171dfae8c065878a2e130390eb78cf2947a5b69-libavcodec/scpr.c-decode_unit CVE-2017-9995
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vx_239, Variable vc_240, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vx_239
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="16"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vc_240
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="256"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_3.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vx_239, Variable vc_240, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_240
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vx_239
		and target_1.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="16"
}

predicate func_2(Variable vx_239, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="lookup"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vx_239
}

predicate func_3(Variable vc_240, ExprStmt target_3) {
		target_3.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vc_240
}

predicate func_4(Variable vc_240, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="freq"
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vc_240
}

from Function func, Variable vx_239, Variable vc_240, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vx_239, vc_240, target_1, target_2, target_3, target_4, func)
and func_1(vx_239, vc_240, target_1)
and func_2(vx_239, target_2)
and func_3(vc_240, target_3)
and func_4(vc_240, target_4)
and vx_239.getType().hasName("unsigned int")
and vc_240.getType().hasName("int")
and vx_239.getParentScope+() = func
and vc_240.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
