/**
 * @name ffmpeg-54655623a82632e7624714d7b2a3e039dc5faa7e-decode_nal_unit
 * @id cpp/ffmpeg/54655623a82632e7624714d7b2a3e039dc5faa7e/decode-nal-unit
 * @description ffmpeg-54655623a82632e7624714d7b2a3e039dc5faa7e-libavcodec/hevcdec.c-decode_nal_unit CVE-2019-11338
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vret_2841, BlockStmt target_14, ReturnStmt target_15) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vret_2841
		and target_0.getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_14
		and target_15.getExpr().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vret_2841) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vret_2841
		and target_1.getRValue().(UnaryMinusExpr).getValue()="-1094995529")
}

predicate func_2(Parameter vs_2837, ValueFieldAccess target_2) {
		target_2.getTarget().getName()="first_slice_in_pic_flag"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="sh"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
}

predicate func_3(Parameter vs_2837, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="avctx"
		and target_3.getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_4(Parameter vs_2837, ValueFieldAccess target_2, IfStmt target_4) {
		target_4.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="max_ra"
		and target_4.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_4.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="2147483647"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nal_unit_type"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nal_unit_type"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="max_ra"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="poc"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_5(Parameter vs_2837, ValueFieldAccess target_2, IfStmt target_5) {
		target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nal_unit_type"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nal_unit_type"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="poc"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="max_ra"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_decoded"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_5.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nal_unit_type"
		and target_5.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_5.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="poc"
		and target_5.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_5.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="max_ra"
		and target_5.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_5.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="max_ra"
		and target_5.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_5.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getValue()="-2147483648"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_6(Parameter vs_2837, ValueFieldAccess target_2, ExprStmt target_6) {
		target_6.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="overlap"
		and target_6.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_7(Variable vret_2841, Parameter vs_2837, ValueFieldAccess target_2, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2841
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("hevc_frame_start")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_2837
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_8(Variable vret_2841, ValueFieldAccess target_2, IfStmt target_8) {
		target_8.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_2841
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_8.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vret_2841
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_9(Parameter vs_2837, ValueFieldAccess target_2, IfStmt target_9) {
		target_9.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ref"
		and target_9.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="First slice in a frame missing.\n"
		and target_9.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_9.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="fail"
		and target_9.getParent().(IfStmt).getCondition()=target_2
}

predicate func_10(PointerFieldAccess target_12, Function func, GotoStmt target_10) {
		target_10.toString() = "goto ..."
		and target_10.getName() ="fail"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_10.getEnclosingFunction() = func
}

predicate func_12(Parameter vs_2837, ValueFieldAccess target_2, PointerFieldAccess target_12) {
		target_12.getTarget().getName()="ref"
		and target_12.getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getQualifier().(VariableAccess).getLocation())
}

predicate func_13(Parameter vs_2837, FunctionCall target_13) {
		target_13.getTarget().hasName("av_log")
		and target_13.getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_13.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_13.getArgument(1) instanceof Literal
		and target_13.getArgument(2).(StringLiteral).getValue()="Two slices reporting being the first in the same frame.\n"
}

predicate func_14(Parameter vs_2837, BlockStmt target_14) {
		target_14.getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="ref"
		and target_14.getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2837
		and target_14.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_14.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof GotoStmt
		and target_14.getStmt(1) instanceof IfStmt
}

predicate func_15(Variable vret_2841, ReturnStmt target_15) {
		target_15.getExpr().(VariableAccess).getTarget()=vret_2841
}

from Function func, Variable vret_2841, Parameter vs_2837, ValueFieldAccess target_2, PointerFieldAccess target_3, IfStmt target_4, IfStmt target_5, ExprStmt target_6, ExprStmt target_7, IfStmt target_8, IfStmt target_9, GotoStmt target_10, PointerFieldAccess target_12, FunctionCall target_13, BlockStmt target_14, ReturnStmt target_15
where
not func_0(vret_2841, target_14, target_15)
and not func_1(vret_2841)
and func_2(vs_2837, target_2)
and func_3(vs_2837, target_3)
and func_4(vs_2837, target_2, target_4)
and func_5(vs_2837, target_2, target_5)
and func_6(vs_2837, target_2, target_6)
and func_7(vret_2841, vs_2837, target_2, target_7)
and func_8(vret_2841, target_2, target_8)
and func_9(vs_2837, target_2, target_9)
and func_10(target_12, func, target_10)
and func_12(vs_2837, target_2, target_12)
and func_13(vs_2837, target_13)
and func_14(vs_2837, target_14)
and func_15(vret_2841, target_15)
and vret_2841.getType().hasName("int")
and vs_2837.getType().hasName("HEVCContext *")
and vret_2841.getParentScope+() = func
and vs_2837.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
