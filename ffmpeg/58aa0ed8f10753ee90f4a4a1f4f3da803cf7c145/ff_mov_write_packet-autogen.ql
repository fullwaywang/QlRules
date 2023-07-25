/**
 * @name ffmpeg-58aa0ed8f10753ee90f4a4a1f4f3da803cf7c145-ff_mov_write_packet
 * @id cpp/ffmpeg/58aa0ed8f10753ee90f4a4a1f4f3da803cf7c145/ff-mov-write-packet
 * @description ffmpeg-58aa0ed8f10753ee90f4a4a1f4f3da803cf7c145-libavformat/movenc.c-ff_mov_write_packet CVE-2020-22016
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtrk_5315, ExprStmt target_7, NotExpr target_8) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrk_5315
		and target_0.getAnOperand().(Literal).getValue()="64"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrk_5315
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtrk_5315, ExprStmt target_9, ExprStmt target_10) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("memset")
		and target_1.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_1.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrk_5315
		and target_1.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_1.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrk_5315
		and target_1.getArgument(1).(Literal).getValue()="0"
		and target_1.getArgument(2).(Literal).getValue()="64"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vtrk_5315, Variable vsize_5318, LogicalAndExpr target_11, NotExpr target_12, ExprStmt target_9) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrk_5315
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_5318
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(Literal).getValue()="64"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vsize_5318, ExprStmt target_9) {
	exists(AddExpr target_3 |
		target_3.getAnOperand().(VariableAccess).getTarget()=vsize_5318
		and target_3.getAnOperand().(Literal).getValue()="64"
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsize_5318
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_4(Variable vtrk_5315, Variable vsize_5318, LogicalAndExpr target_11, NotExpr target_12, ExprStmt target_13, ExprStmt target_10) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrk_5315
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_5318
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_4.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="64"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_12.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vtrk_5315, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="vos_len"
		and target_5.getQualifier().(VariableAccess).getTarget()=vtrk_5315
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
}

predicate func_6(Variable vsize_5318, VariableAccess target_6) {
		target_6.getTarget()=vsize_5318
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
}

predicate func_7(Variable vtrk_5315, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrk_5315
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrk_5315
}

predicate func_8(Variable vtrk_5315, NotExpr target_8) {
		target_8.getOperand().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_8.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrk_5315
}

predicate func_9(Variable vtrk_5315, Variable vsize_5318, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrk_5315
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsize_5318
}

predicate func_10(Variable vtrk_5315, Variable vsize_5318, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrk_5315
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsize_5318
}

predicate func_11(Variable vtrk_5315, LogicalAndExpr target_11) {
		target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="codec_id"
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="codec_id"
		and target_11.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="codec_id"
		and target_11.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_11.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrk_5315
}

predicate func_12(Variable vtrk_5315, NotExpr target_12) {
		target_12.getOperand().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_12.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrk_5315
}

predicate func_13(Variable vtrk_5315, Variable vsize_5318, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrk_5315
		and target_13.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_13.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsize_5318
}

from Function func, Variable vtrk_5315, Variable vsize_5318, PointerFieldAccess target_5, VariableAccess target_6, ExprStmt target_7, NotExpr target_8, ExprStmt target_9, ExprStmt target_10, LogicalAndExpr target_11, NotExpr target_12, ExprStmt target_13
where
not func_0(vtrk_5315, target_7, target_8)
and not func_1(vtrk_5315, target_9, target_10)
and not func_2(vtrk_5315, vsize_5318, target_11, target_12, target_9)
and not func_4(vtrk_5315, vsize_5318, target_11, target_12, target_13, target_10)
and func_5(vtrk_5315, target_5)
and func_6(vsize_5318, target_6)
and func_7(vtrk_5315, target_7)
and func_8(vtrk_5315, target_8)
and func_9(vtrk_5315, vsize_5318, target_9)
and func_10(vtrk_5315, vsize_5318, target_10)
and func_11(vtrk_5315, target_11)
and func_12(vtrk_5315, target_12)
and func_13(vtrk_5315, vsize_5318, target_13)
and vtrk_5315.getType().hasName("MOVTrack *")
and vsize_5318.getType().hasName("int")
and vtrk_5315.getParentScope+() = func
and vsize_5318.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
