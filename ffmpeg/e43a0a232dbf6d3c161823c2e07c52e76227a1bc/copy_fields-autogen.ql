/**
 * @name ffmpeg-e43a0a232dbf6d3c161823c2e07c52e76227a1bc-copy_fields
 * @id cpp/ffmpeg/e43a0a232dbf6d3c161823c2e07c52e76227a1bc/copy-fields
 * @description ffmpeg-e43a0a232dbf6d3c161823c2e07c52e76227a1bc-libavfilter/vf_fieldmatch.c-copy_fields CVE-2013-4263
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsrc_608, Variable vplane_610, ExprStmt target_2, LogicalAndExpr target_1, ExprStmt target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_608
		and target_0.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_610
		and target_0.getParent().(ForStmt).getStmt()=target_2
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsrc_608, Variable vplane_610, ExprStmt target_2, LogicalAndExpr target_1) {
		target_1.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vplane_610
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_1.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_608
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_610
		and target_1.getParent().(ForStmt).getStmt()=target_2
}

predicate func_2(Parameter vsrc_608, Variable vplane_610, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("av_image_copy_plane")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVFrame *")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_610
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVFrame *")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_610
		and target_2.getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_2.getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVFrame *")
		and target_2.getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_610
		and target_2.getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_608
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_610
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_608
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_610
		and target_2.getExpr().(FunctionCall).getArgument(3).(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_2.getExpr().(FunctionCall).getArgument(3).(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_608
		and target_2.getExpr().(FunctionCall).getArgument(3).(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_610
		and target_2.getExpr().(FunctionCall).getArgument(3).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_2.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("get_width")
		and target_2.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const FieldMatchContext *")
		and target_2.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsrc_608
		and target_2.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplane_610
		and target_2.getExpr().(FunctionCall).getArgument(5).(DivExpr).getLeftOperand().(FunctionCall).getTarget().hasName("get_height")
		and target_2.getExpr().(FunctionCall).getArgument(5).(DivExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const FieldMatchContext *")
		and target_2.getExpr().(FunctionCall).getArgument(5).(DivExpr).getLeftOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsrc_608
		and target_2.getExpr().(FunctionCall).getArgument(5).(DivExpr).getLeftOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vplane_610
		and target_2.getExpr().(FunctionCall).getArgument(5).(DivExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_3(Variable vplane_610, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vplane_610
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vsrc_608, Variable vplane_610, LogicalAndExpr target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vsrc_608, vplane_610, target_2, target_1, target_3)
and func_1(vsrc_608, vplane_610, target_2, target_1)
and func_2(vsrc_608, vplane_610, target_2)
and func_3(vplane_610, target_3)
and vsrc_608.getType().hasName("const AVFrame *")
and vplane_610.getType().hasName("int")
and vsrc_608.getFunction() = func
and vplane_610.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
