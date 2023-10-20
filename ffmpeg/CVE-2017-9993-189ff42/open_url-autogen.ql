/**
 * @name ffmpeg-189ff4219644532bdfa7bab28dfedaee4d6d4021-open_url
 * @id cpp/ffmpeg/189ff4219644532bdfa7bab28dfedaee4d6d4021/open-url
 * @description ffmpeg-189ff4219644532bdfa7bab28dfedaee4d6d4021-libavformat/hls.c-open_url CVE-2017-9993
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_598, Parameter vurl_598, Variable vc_601, LogicalAndExpr target_10, ExprStmt target_11, ExprStmt target_12, LogicalAndExpr target_13, ExprStmt target_14) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="allowed_extensions"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_601
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ALL"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("av_match_ext")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vurl_598
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="allowed_extensions"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_601
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_598
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Filename extension of '%s' is not a common multimedia extension, blocked for security reasons.\nIf you wish to override this adjust allowed_extensions, you can set it to 'ALL' to allow all\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vurl_598
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_1(Variable vc_601) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("strcmp")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="allowed_extensions"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_601
		and target_1.getArgument(1).(StringLiteral).getValue()="ALL")
}

*/
/*predicate func_2(Parameter vurl_598, Variable vc_601, ExprStmt target_12, ExprStmt target_14) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("av_match_ext")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vurl_598
		and target_2.getArgument(1).(PointerFieldAccess).getTarget().getName()="allowed_extensions"
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_601
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getArgument(0).(VariableAccess).getLocation())
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_4(LogicalAndExpr target_10, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition() instanceof FunctionCall
		and target_4.getThen().(BlockStmt).getStmt(0).(EmptyStmt).toString() = ";"
		and target_4.getElse().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_4.getParent().(IfStmt).getCondition()=target_10
		and target_4.getEnclosingFunction() = func)
}

/*predicate func_5(Function func, UnaryMinusExpr target_5) {
		target_5.getValue()="-1094995529"
		and target_5.getEnclosingFunction() = func
}

*/
predicate func_6(Variable vproto_name_603, FunctionCall target_6) {
		target_6.getTarget().hasName("av_strstart")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vproto_name_603
		and target_6.getArgument(1).(StringLiteral).getValue()="http"
		and target_6.getArgument(2).(Literal).getValue()="0"
}

predicate func_7(Variable vproto_name_603, FunctionCall target_7) {
		target_7.getTarget().hasName("av_strstart")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vproto_name_603
		and target_7.getArgument(1).(StringLiteral).getValue()="file"
		and target_7.getArgument(2).(Literal).getValue()="0"
}

predicate func_8(LogicalAndExpr target_10, Function func, ReturnStmt target_8) {
		target_8.getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_8.getParent().(IfStmt).getCondition()=target_10
		and target_8.getEnclosingFunction() = func
}

predicate func_9(ReturnStmt target_8, Function func, NotExpr target_9) {
		target_9.getOperand() instanceof FunctionCall
		and target_9.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_8
		and target_9.getEnclosingFunction() = func
}

predicate func_10(LogicalAndExpr target_10) {
		target_10.getAnOperand().(NotExpr).getOperand() instanceof FunctionCall
		and target_10.getAnOperand() instanceof NotExpr
}

predicate func_11(Parameter vs_598, Parameter vurl_598, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="io_open"
		and target_11.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_598
		and target_11.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vs_598
		and target_11.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vurl_598
		and target_11.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(3).(Literal).getValue()="1"
}

predicate func_12(Parameter vurl_598, Variable vproto_name_603, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vproto_name_603
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("avio_find_protocol_name")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vurl_598
}

predicate func_13(Parameter vurl_598, Variable vproto_name_603, LogicalAndExpr target_13) {
		target_13.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_13.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vproto_name_603
		and target_13.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vurl_598
		and target_13.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("strlen")
		and target_13.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vproto_name_603
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vurl_598
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(FunctionCall).getTarget().hasName("strlen")
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vproto_name_603
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="58"
}

predicate func_14(Variable vc_601, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("av_free")
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cookies"
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_601
}

from Function func, Parameter vs_598, Parameter vurl_598, Variable vc_601, Variable vproto_name_603, FunctionCall target_6, FunctionCall target_7, ReturnStmt target_8, NotExpr target_9, LogicalAndExpr target_10, ExprStmt target_11, ExprStmt target_12, LogicalAndExpr target_13, ExprStmt target_14
where
not func_0(vs_598, vurl_598, vc_601, target_10, target_11, target_12, target_13, target_14)
and not func_4(target_10, func)
and func_6(vproto_name_603, target_6)
and func_7(vproto_name_603, target_7)
and func_8(target_10, func, target_8)
and func_9(target_8, func, target_9)
and func_10(target_10)
and func_11(vs_598, vurl_598, target_11)
and func_12(vurl_598, vproto_name_603, target_12)
and func_13(vurl_598, vproto_name_603, target_13)
and func_14(vc_601, target_14)
and vs_598.getType().hasName("AVFormatContext *")
and vurl_598.getType().hasName("const char *")
and vc_601.getType().hasName("HLSContext *")
and vproto_name_603.getType().hasName("const char *")
and vs_598.getParentScope+() = func
and vurl_598.getParentScope+() = func
and vc_601.getParentScope+() = func
and vproto_name_603.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
