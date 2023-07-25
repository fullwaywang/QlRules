/**
 * @name ffmpeg-5ea091fb5a12dc0210b8efdf30b573b87e21652b-asfrtp_parse_packet
 * @id cpp/ffmpeg/5ea091fb5a12dc0210b8efdf30b573b87e21652b/asfrtp-parse-packet
 * @description ffmpeg-5ea091fb5a12dc0210b8efdf30b573b87e21652b-libavformat/rtpdec_asf.c-asfrtp_parse_packet CVE-2011-4031
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_166, Variable voff_176, Variable vcur_len_234, NotExpr target_6, SubExpr target_7, ConditionalExpr target_8, SubExpr target_9, PointerArithmeticOperation target_10, ExprStmt target_11) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_len_234
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_166
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voff_176
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getThen().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_166
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getThen().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voff_176
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vcur_len_234
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(4)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_7.getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_8.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_9.getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(VariableAccess).getLocation())
		and target_11.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Function func) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("void *")
		and target_1.getRValue() instanceof FunctionCall
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(NotExpr target_6, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("void *")
		and target_2.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(6)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vasf_163, NotExpr target_6, ExprStmt target_12) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vasf_163
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("void *")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(7)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vasf_163, Variable vout_len_176, FunctionCall target_5) {
		target_5.getTarget().hasName("av_realloc")
		and target_5.getArgument(0).(PointerFieldAccess).getTarget().getName()="buf"
		and target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vasf_163
		and target_5.getArgument(1).(VariableAccess).getTarget()=vout_len_176
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_5.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vasf_163
}

predicate func_6(NotExpr target_6) {
		target_6.getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="64"
}

predicate func_7(Parameter vlen_166, Variable voff_176, SubExpr target_7) {
		target_7.getLeftOperand().(VariableAccess).getTarget()=vlen_166
		and target_7.getRightOperand().(VariableAccess).getTarget()=voff_176
}

predicate func_8(Parameter vlen_166, Variable voff_176, Variable vcur_len_234, ConditionalExpr target_8) {
		target_8.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_len_234
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_166
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voff_176
		and target_8.getThen().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_166
		and target_8.getThen().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voff_176
		and target_8.getElse().(VariableAccess).getTarget()=vcur_len_234
}

predicate func_9(Variable voff_176, SubExpr target_9) {
		target_9.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_9.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_9.getRightOperand().(VariableAccess).getTarget()=voff_176
}

predicate func_10(Variable voff_176, PointerArithmeticOperation target_10) {
		target_10.getAnOperand().(VariableAccess).getTarget().getType().hasName("const uint8_t *")
		and target_10.getAnOperand().(VariableAccess).getTarget()=voff_176
}

predicate func_11(Variable vout_len_176, Variable vcur_len_234, ExprStmt target_11) {
		target_11.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vout_len_176
		and target_11.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vcur_len_234
}

predicate func_12(Parameter vasf_163, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pktbuf"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vasf_163
		and target_12.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vasf_163, Parameter vlen_166, Variable voff_176, Variable vout_len_176, Variable vcur_len_234, FunctionCall target_5, NotExpr target_6, SubExpr target_7, ConditionalExpr target_8, SubExpr target_9, PointerArithmeticOperation target_10, ExprStmt target_11, ExprStmt target_12
where
not func_0(vlen_166, voff_176, vcur_len_234, target_6, target_7, target_8, target_9, target_10, target_11)
and not func_1(func)
and not func_2(target_6, func)
and not func_3(vasf_163, target_6, target_12)
and func_5(vasf_163, vout_len_176, target_5)
and func_6(target_6)
and func_7(vlen_166, voff_176, target_7)
and func_8(vlen_166, voff_176, vcur_len_234, target_8)
and func_9(voff_176, target_9)
and func_10(voff_176, target_10)
and func_11(vout_len_176, vcur_len_234, target_11)
and func_12(vasf_163, target_12)
and vasf_163.getType().hasName("PayloadContext *")
and vlen_166.getType().hasName("int")
and voff_176.getType().hasName("int")
and vout_len_176.getType().hasName("int")
and vcur_len_234.getType().hasName("int")
and vasf_163.getFunction() = func
and vlen_166.getFunction() = func
and voff_176.(LocalVariable).getFunction() = func
and vout_len_176.(LocalVariable).getFunction() = func
and vcur_len_234.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
