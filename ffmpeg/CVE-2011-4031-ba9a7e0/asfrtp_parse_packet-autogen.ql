/**
 * @name ffmpeg-ba9a7e0d71bd34f8b89ae99322b62a310be163a6-asfrtp_parse_packet
 * @id cpp/ffmpeg/ba9a7e0d71bd34f8b89ae99322b62a310be163a6/asfrtp-parse-packet
 * @description ffmpeg-ba9a7e0d71bd34f8b89ae99322b62a310be163a6-libavformat/rtpdec_asf.c-asfrtp_parse_packet CVE-2011-4031
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vasf_163, Parameter vlen_166, Variable voff_176, Variable vcur_len_234, NotExpr target_1, ExprStmt target_2, PointerArithmeticOperation target_3, SubExpr target_4, ConditionalExpr target_5, SubExpr target_6, PointerArithmeticOperation target_7, ExprStmt target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vasf_163
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_len_234
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_166
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voff_176
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getThen().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_166
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getThen().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voff_176
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vcur_len_234
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(4)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_5.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_6.getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(NotExpr target_1) {
		target_1.getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="64"
}

predicate func_2(Parameter vasf_163, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vasf_163
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_realloc")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buf"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vasf_163
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_3(Parameter vasf_163, PointerArithmeticOperation target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vasf_163
		and target_3.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_4(Parameter vlen_166, Variable voff_176, SubExpr target_4) {
		target_4.getLeftOperand().(VariableAccess).getTarget()=vlen_166
		and target_4.getRightOperand().(VariableAccess).getTarget()=voff_176
}

predicate func_5(Parameter vlen_166, Variable voff_176, Variable vcur_len_234, ConditionalExpr target_5) {
		target_5.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_len_234
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_166
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voff_176
		and target_5.getThen().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_166
		and target_5.getThen().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voff_176
		and target_5.getElse().(VariableAccess).getTarget()=vcur_len_234
}

predicate func_6(Variable voff_176, SubExpr target_6) {
		target_6.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getRightOperand().(VariableAccess).getTarget()=voff_176
}

predicate func_7(Variable voff_176, PointerArithmeticOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget().getType().hasName("const uint8_t *")
		and target_7.getAnOperand().(VariableAccess).getTarget()=voff_176
}

predicate func_8(Variable vcur_len_234, ExprStmt target_8) {
		target_8.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vcur_len_234
}

from Function func, Parameter vasf_163, Parameter vlen_166, Variable voff_176, Variable vcur_len_234, NotExpr target_1, ExprStmt target_2, PointerArithmeticOperation target_3, SubExpr target_4, ConditionalExpr target_5, SubExpr target_6, PointerArithmeticOperation target_7, ExprStmt target_8
where
not func_0(vasf_163, vlen_166, voff_176, vcur_len_234, target_1, target_2, target_3, target_4, target_5, target_6, target_7, target_8)
and func_1(target_1)
and func_2(vasf_163, target_2)
and func_3(vasf_163, target_3)
and func_4(vlen_166, voff_176, target_4)
and func_5(vlen_166, voff_176, vcur_len_234, target_5)
and func_6(voff_176, target_6)
and func_7(voff_176, target_7)
and func_8(vcur_len_234, target_8)
and vasf_163.getType().hasName("PayloadContext *")
and vlen_166.getType().hasName("int")
and voff_176.getType().hasName("int")
and vcur_len_234.getType().hasName("int")
and vasf_163.getFunction() = func
and vlen_166.getFunction() = func
and voff_176.(LocalVariable).getFunction() = func
and vcur_len_234.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
