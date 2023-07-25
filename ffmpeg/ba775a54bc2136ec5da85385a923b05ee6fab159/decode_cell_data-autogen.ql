/**
 * @name ffmpeg-ba775a54bc2136ec5da85385a923b05ee6fab159-decode_cell_data
 * @id cpp/ffmpeg/ba775a54bc2136ec5da85385a923b05ee6fab159/decode-cell-data
 * @description ffmpeg-ba775a54bc2136ec5da85385a923b05ee6fab159-libavcodec/indeo3.c-decode_cell_data CVE-2012-2776
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vv_zoom_405, Variable vy_409, BlockStmt target_4, ExprStmt target_5, CommaExpr target_6, ExprStmt target_7) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vy_409
		and target_0.getAnOperand().(VariableAccess).getTarget()=vv_zoom_405
		and target_0.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vy_409
		and target_0.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_0.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Cell *")
		and target_0.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_4
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getRightOperand().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vh_zoom_405, Variable vx_409, BlockStmt target_8, AssignAddExpr target_9, ExprStmt target_10) {
	exists(AddExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vx_409
		and target_1.getAnOperand().(VariableAccess).getTarget()=vh_zoom_405
		and target_1.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vx_409
		and target_1.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_1.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Cell *")
		and target_1.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_8
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_9.getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vy_409, BlockStmt target_4, VariableAccess target_2) {
		target_2.getTarget()=vy_409
		and target_2.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_2.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Cell *")
		and target_2.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_4
}

predicate func_3(Variable vx_409, BlockStmt target_8, VariableAccess target_3) {
		target_3.getTarget()=vx_409
		and target_3.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_3.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Cell *")
		and target_3.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_8
}

predicate func_4(Parameter vh_zoom_405, Variable vx_409, BlockStmt target_4) {
		target_4.getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx_409
		and target_4.getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getStmt(0).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vx_409
		and target_4.getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_4.getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Cell *")
		and target_4.getStmt(0).(ForStmt).getUpdate().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vx_409
		and target_4.getStmt(0).(ForStmt).getUpdate().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_4.getStmt(0).(ForStmt).getUpdate().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vh_zoom_405
		and target_4.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_4.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_4.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_4.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_4.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getStmt(0).(ForStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
}

predicate func_5(Parameter vv_zoom_405, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vv_zoom_405
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

predicate func_6(Parameter vv_zoom_405, Variable vy_409, CommaExpr target_6) {
		target_6.getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getLeftOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getRightOperand().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vy_409
		and target_6.getRightOperand().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_6.getRightOperand().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vv_zoom_405
}

predicate func_7(Variable vy_409, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy_409
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_8(BlockStmt target_8) {
		target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_8.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_8.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_8.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_8.getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_8.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_8.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_8.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
}

predicate func_9(Parameter vh_zoom_405, Variable vx_409, AssignAddExpr target_9) {
		target_9.getLValue().(VariableAccess).getTarget()=vx_409
		and target_9.getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_9.getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vh_zoom_405
}

predicate func_10(Variable vx_409, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx_409
		and target_10.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vh_zoom_405, Parameter vv_zoom_405, Variable vx_409, Variable vy_409, VariableAccess target_2, VariableAccess target_3, BlockStmt target_4, ExprStmt target_5, CommaExpr target_6, ExprStmt target_7, BlockStmt target_8, AssignAddExpr target_9, ExprStmt target_10
where
not func_0(vv_zoom_405, vy_409, target_4, target_5, target_6, target_7)
and not func_1(vh_zoom_405, vx_409, target_8, target_9, target_10)
and func_2(vy_409, target_4, target_2)
and func_3(vx_409, target_8, target_3)
and func_4(vh_zoom_405, vx_409, target_4)
and func_5(vv_zoom_405, target_5)
and func_6(vv_zoom_405, vy_409, target_6)
and func_7(vy_409, target_7)
and func_8(target_8)
and func_9(vh_zoom_405, vx_409, target_9)
and func_10(vx_409, target_10)
and vh_zoom_405.getType().hasName("int")
and vv_zoom_405.getType().hasName("int")
and vx_409.getType().hasName("int")
and vy_409.getType().hasName("int")
and vh_zoom_405.getFunction() = func
and vv_zoom_405.getFunction() = func
and vx_409.(LocalVariable).getFunction() = func
and vy_409.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
