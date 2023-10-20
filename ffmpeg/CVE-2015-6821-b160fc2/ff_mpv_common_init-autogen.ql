/**
 * @name ffmpeg-b160fc290cf49b516c5b6ee0730fd9da7fc623b1-ff_mpv_common_init
 * @id cpp/ffmpeg/b160fc290cf49b516c5b6ee0730fd9da7fc623b1/ff-mpv-common-init
 * @description ffmpeg-b160fc290cf49b516c5b6ee0730fd9da7fc623b1-libavcodec/mpegvideo.c-ff_mpv_common_init CVE-2015-6821
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_792, ArrayExpr target_6) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("clear_context")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vs_792
		and target_6.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_792, VariableAccess target_1) {
		target_1.getTarget()=vs_792
}

predicate func_2(Parameter vs_792, FunctionCall target_2) {
		target_2.getTarget().hasName("memset")
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="next_picture"
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_792
		and target_2.getArgument(1).(Literal).getValue()="0"
		and target_2.getArgument(2).(SizeofExprOperator).getValue()="320"
}

predicate func_3(Parameter vs_792, Function func, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="last_picture"
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_792
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="320"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Parameter vs_792, Function func, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="current_picture"
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_792
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_4.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="320"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Parameter vs_792, Function func, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="new_picture"
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_792
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_5.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="320"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Parameter vs_792, ArrayExpr target_6) {
		target_6.getArrayBase().(PointerFieldAccess).getTarget().getName()="picture"
		and target_6.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_792
}

from Function func, Parameter vs_792, VariableAccess target_1, FunctionCall target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ArrayExpr target_6
where
not func_0(vs_792, target_6)
and func_1(vs_792, target_1)
and func_2(vs_792, target_2)
and func_3(vs_792, func, target_3)
and func_4(vs_792, func, target_4)
and func_5(vs_792, func, target_5)
and func_6(vs_792, target_6)
and vs_792.getType().hasName("MpegEncContext *")
and vs_792.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
