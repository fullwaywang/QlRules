/**
 * @name ffmpeg-124eb202e70678539544f6268efc98131f19fa49-ivr_read_header
 * @id cpp/ffmpeg/124eb202e70678539544f6268efc98131f19fa49/ivr-read-header
 * @description ffmpeg-124eb202e70678539544f6268efc98131f19fa49-libavformat/rmdec.c-ivr_read_header CVE-2017-14054
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1171, Variable vlen_1173, Variable vj_1174, Variable vpb_1176, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, RelationalOperation target_6, FunctionCall target_7) {
	exists(ForStmt target_0 |
		target_0.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vj_1174
		and target_0.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vj_1174
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_1173
		and target_0.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vj_1174
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("avio_feof")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_1176
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1171
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="48"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%X"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("avio_r8")
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_1176
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_1171, Variable vlen_1173, Variable vj_1174, Variable vpb_1176, EqualityOperation target_2, ForStmt target_1) {
		target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vj_1174
		and target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vj_1174
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_1173
		and target_1.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vj_1174
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1171
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="48"
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%X"
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("avio_r8")
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_1176
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(EqualityOperation target_2) {
		target_2.getAnOperand().(Literal).getValue()="4"
}

predicate func_3(Parameter vs_1171, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1171
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="48"
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s = '0x"
}

predicate func_4(Parameter vs_1171, Variable vpb_1176, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1171
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="48"
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%X"
		and target_4.getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("avio_r8")
		and target_4.getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_1176
}

predicate func_5(Variable vlen_1173, Variable vpb_1176, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("avio_get_str")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_1176
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_1173
		and target_5.getExpr().(FunctionCall).getArgument(3).(SizeofExprOperator).getValue()="256"
}

predicate func_6(Variable vlen_1173, Variable vj_1174, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget()=vj_1174
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vlen_1173
}

predicate func_7(Variable vpb_1176, FunctionCall target_7) {
		target_7.getTarget().hasName("avio_r8")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vpb_1176
}

from Function func, Parameter vs_1171, Variable vlen_1173, Variable vj_1174, Variable vpb_1176, ForStmt target_1, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, RelationalOperation target_6, FunctionCall target_7
where
not func_0(vs_1171, vlen_1173, vj_1174, vpb_1176, target_2, target_3, target_4, target_5, target_6, target_7)
and func_1(vs_1171, vlen_1173, vj_1174, vpb_1176, target_2, target_1)
and func_2(target_2)
and func_3(vs_1171, target_3)
and func_4(vs_1171, vpb_1176, target_4)
and func_5(vlen_1173, vpb_1176, target_5)
and func_6(vlen_1173, vj_1174, target_6)
and func_7(vpb_1176, target_7)
and vs_1171.getType().hasName("AVFormatContext *")
and vlen_1173.getType().hasName("unsigned int")
and vj_1174.getType().hasName("int")
and vpb_1176.getType().hasName("AVIOContext *")
and vs_1171.getParentScope+() = func
and vlen_1173.getParentScope+() = func
and vj_1174.getParentScope+() = func
and vpb_1176.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
