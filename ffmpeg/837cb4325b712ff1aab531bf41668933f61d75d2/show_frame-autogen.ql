/**
 * @name ffmpeg-837cb4325b712ff1aab531bf41668933f61d75d2-show_frame
 * @id cpp/ffmpeg/837cb4325b712ff1aab531bf41668933f61d75d2/show-frame
 * @description ffmpeg-837cb4325b712ff1aab531bf41668933f61d75d2-ffprobe.c-show_frame CVE-2017-14225
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vw_2057, Parameter vframe_2057, ExprStmt target_5, FunctionCall target_7, FunctionCall target_8) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("print_primaries")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vw_2057
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="color_primaries"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_2057
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vframe_2057, ExprStmt target_9, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="color_primaries"
		and target_1.getQualifier().(VariableAccess).getTarget()=vframe_2057
		and target_1.getParent().(NEExpr).getAnOperand() instanceof EnumConstantAccess
		and target_1.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_9
}

predicate func_2(Parameter vw_2057, VariableAccess target_2) {
		target_2.getTarget()=vw_2057
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_3(Parameter vw_2057, Parameter vframe_2057, PointerFieldAccess target_10, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="color_primaries"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_2057
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("writer_print_string")
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vw_2057
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="color_primaries"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("av_color_primaries_name")
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="color_primaries"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_2057
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("writer_print_string")
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vw_2057
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="color_primaries"
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("av_color_primaries_name")
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="color_primaries"
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_2057
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_10
}

/*predicate func_4(Parameter vw_2057, Parameter vframe_2057, FunctionCall target_4) {
		target_4.getTarget().hasName("writer_print_string")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vw_2057
		and target_4.getArgument(1).(StringLiteral).getValue()="color_primaries"
		and target_4.getArgument(2).(FunctionCall).getTarget().hasName("av_color_primaries_name")
		and target_4.getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="color_primaries"
		and target_4.getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_2057
		and target_4.getArgument(3).(Literal).getValue()="0"
}

*/
predicate func_5(Parameter vw_2057, Parameter vframe_2057, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("writer_print_string")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vw_2057
		and target_5.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="color_space"
		and target_5.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("av_color_space_name")
		and target_5.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="colorspace"
		and target_5.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_2057
		and target_5.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
}

predicate func_7(Parameter vframe_2057, FunctionCall target_7) {
		target_7.getTarget().hasName("av_color_space_name")
		and target_7.getArgument(0).(PointerFieldAccess).getTarget().getName()="colorspace"
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_2057
}

predicate func_8(Parameter vframe_2057, FunctionCall target_8) {
		target_8.getTarget().hasName("av_color_primaries_name")
		and target_8.getArgument(0).(PointerFieldAccess).getTarget().getName()="color_primaries"
		and target_8.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_2057
}

predicate func_9(ExprStmt target_9) {
		target_9.getExpr() instanceof FunctionCall
}

predicate func_10(PointerFieldAccess target_10) {
		target_10.getTarget().getName()="codec_type"
		and target_10.getQualifier().(PointerFieldAccess).getTarget().getName()="codecpar"
}

from Function func, Parameter vw_2057, Parameter vframe_2057, PointerFieldAccess target_1, VariableAccess target_2, IfStmt target_3, ExprStmt target_5, FunctionCall target_7, FunctionCall target_8, ExprStmt target_9, PointerFieldAccess target_10
where
not func_0(vw_2057, vframe_2057, target_5, target_7, target_8)
and func_1(vframe_2057, target_9, target_1)
and func_2(vw_2057, target_2)
and func_3(vw_2057, vframe_2057, target_10, target_3)
and func_5(vw_2057, vframe_2057, target_5)
and func_7(vframe_2057, target_7)
and func_8(vframe_2057, target_8)
and func_9(target_9)
and func_10(target_10)
and vw_2057.getType().hasName("WriterContext *")
and vframe_2057.getType().hasName("AVFrame *")
and vw_2057.getParentScope+() = func
and vframe_2057.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
