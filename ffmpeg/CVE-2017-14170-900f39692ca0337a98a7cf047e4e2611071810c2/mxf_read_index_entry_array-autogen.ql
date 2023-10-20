/**
 * @name ffmpeg-900f39692ca0337a98a7cf047e4e2611071810c2-mxf_read_index_entry_array
 * @id cpp/ffmpeg/900f39692ca0337a98a7cf047e4e2611071810c2/mxf-read-index-entry-array
 * @description ffmpeg-900f39692ca0337a98a7cf047e4e2611071810c2-libavformat/mxfdec.c-mxf_read_index_entry_array CVE-2017-14170
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsegment_895, Variable vlength_897, ExprStmt target_2, LogicalOrExpr target_3, ExprStmt target_4, SubExpr target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="nb_index_entries"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsegment_895
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlength_897
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="11"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_5.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpb_895, ExprStmt target_4, ExprStmt target_6) {
	exists(IfStmt target_1 |
		target_1.getCondition().(FunctionCall).getTarget().hasName("avio_feof")
		and target_1.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_895
		and target_1.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vpb_895, Parameter vsegment_895, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nb_index_entries"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsegment_895
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("avio_rb32")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_895
}

predicate func_3(Parameter vsegment_895, LogicalOrExpr target_3) {
		target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="temporal_offset_entries"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsegment_895
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_calloc")
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="nb_index_entries"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsegment_895
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flag_entries"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsegment_895
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_calloc")
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="nb_index_entries"
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsegment_895
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="4"
		and target_3.getAnOperand().(NotExpr).getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="stream_offset_entries"
		and target_3.getAnOperand().(NotExpr).getOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsegment_895
		and target_3.getAnOperand().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_calloc")
		and target_3.getAnOperand().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="nb_index_entries"
		and target_3.getAnOperand().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsegment_895
		and target_3.getAnOperand().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="8"
}

predicate func_4(Parameter vpb_895, Variable vlength_897, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_897
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("avio_rb32")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_895
}

predicate func_5(Variable vlength_897, SubExpr target_5) {
		target_5.getLeftOperand().(VariableAccess).getTarget()=vlength_897
		and target_5.getRightOperand().(Literal).getValue()="11"
}

predicate func_6(Parameter vpb_895, Parameter vsegment_895, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="temporal_offset_entries"
		and target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsegment_895
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("avio_r8")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_895
}

from Function func, Parameter vpb_895, Parameter vsegment_895, Variable vlength_897, ExprStmt target_2, LogicalOrExpr target_3, ExprStmt target_4, SubExpr target_5, ExprStmt target_6
where
not func_0(vsegment_895, vlength_897, target_2, target_3, target_4, target_5, func)
and not func_1(vpb_895, target_4, target_6)
and func_2(vpb_895, vsegment_895, target_2)
and func_3(vsegment_895, target_3)
and func_4(vpb_895, vlength_897, target_4)
and func_5(vlength_897, target_5)
and func_6(vpb_895, vsegment_895, target_6)
and vpb_895.getType().hasName("AVIOContext *")
and vsegment_895.getType().hasName("MXFIndexTableSegment *")
and vlength_897.getType().hasName("int")
and vpb_895.getParentScope+() = func
and vsegment_895.getParentScope+() = func
and vlength_897.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
