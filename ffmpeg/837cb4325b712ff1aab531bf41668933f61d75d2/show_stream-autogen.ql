/**
 * @name ffmpeg-837cb4325b712ff1aab531bf41668933f61d75d2-show_stream
 * @id cpp/ffmpeg/837cb4325b712ff1aab531bf41668933f61d75d2/show-stream
 * @description ffmpeg-837cb4325b712ff1aab531bf41668933f61d75d2-ffprobe.c-show_stream CVE-2017-14225
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpar_2425, Parameter vw_2422, FunctionCall target_5, FunctionCall target_6, ExprStmt target_7) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("print_primaries")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vw_2422
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="color_primaries"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpar_2425
		and target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vpar_2425, ExprStmt target_9, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="color_primaries"
		and target_1.getQualifier().(VariableAccess).getTarget()=vpar_2425
		and target_1.getParent().(NEExpr).getAnOperand() instanceof EnumConstantAccess
		and target_1.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_9
}

predicate func_2(Parameter vw_2422, VariableAccess target_2) {
		target_2.getTarget()=vw_2422
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_3(Variable vpar_2425, Parameter vw_2422, PointerFieldAccess target_10, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="color_primaries"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpar_2425
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("writer_print_string")
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vw_2422
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="color_primaries"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("av_color_primaries_name")
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="color_primaries"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpar_2425
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("writer_print_string")
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vw_2422
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="color_primaries"
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("av_color_primaries_name")
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="color_primaries"
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpar_2425
		and target_3.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_10
}

/*predicate func_4(Variable vpar_2425, Parameter vw_2422, FunctionCall target_4) {
		target_4.getTarget().hasName("writer_print_string")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vw_2422
		and target_4.getArgument(1).(StringLiteral).getValue()="color_primaries"
		and target_4.getArgument(2).(FunctionCall).getTarget().hasName("av_color_primaries_name")
		and target_4.getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="color_primaries"
		and target_4.getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpar_2425
		and target_4.getArgument(3).(Literal).getValue()="0"
}

*/
predicate func_5(Variable vpar_2425, FunctionCall target_5) {
		target_5.getTarget().hasName("av_color_transfer_name")
		and target_5.getArgument(0).(PointerFieldAccess).getTarget().getName()="color_trc"
		and target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpar_2425
}

predicate func_6(Variable vpar_2425, FunctionCall target_6) {
		target_6.getTarget().hasName("av_color_primaries_name")
		and target_6.getArgument(0).(PointerFieldAccess).getTarget().getName()="color_primaries"
		and target_6.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpar_2425
}

predicate func_7(Variable vpar_2425, Parameter vw_2422, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("writer_print_string")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vw_2422
		and target_7.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="color_transfer"
		and target_7.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("av_color_transfer_name")
		and target_7.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="color_trc"
		and target_7.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpar_2425
		and target_7.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
}

predicate func_9(ExprStmt target_9) {
		target_9.getExpr() instanceof FunctionCall
}

predicate func_10(Variable vpar_2425, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="codec_type"
		and target_10.getQualifier().(VariableAccess).getTarget()=vpar_2425
}

from Function func, Variable vpar_2425, Parameter vw_2422, PointerFieldAccess target_1, VariableAccess target_2, IfStmt target_3, FunctionCall target_5, FunctionCall target_6, ExprStmt target_7, ExprStmt target_9, PointerFieldAccess target_10
where
not func_0(vpar_2425, vw_2422, target_5, target_6, target_7)
and func_1(vpar_2425, target_9, target_1)
and func_2(vw_2422, target_2)
and func_3(vpar_2425, vw_2422, target_10, target_3)
and func_5(vpar_2425, target_5)
and func_6(vpar_2425, target_6)
and func_7(vpar_2425, vw_2422, target_7)
and func_9(target_9)
and func_10(vpar_2425, target_10)
and vpar_2425.getType().hasName("AVCodecParameters *")
and vw_2422.getType().hasName("WriterContext *")
and vpar_2425.getParentScope+() = func
and vw_2422.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
