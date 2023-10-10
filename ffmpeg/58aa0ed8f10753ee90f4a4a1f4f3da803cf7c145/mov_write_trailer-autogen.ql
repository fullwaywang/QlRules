/**
 * @name ffmpeg-58aa0ed8f10753ee90f4a4a1f4f3da803cf7c145-mov_write_trailer
 * @id cpp/ffmpeg/58aa0ed8f10753ee90f4a4a1f4f3da803cf7c145/mov-write-trailer
 * @description ffmpeg-58aa0ed8f10753ee90f4a4a1f4f3da803cf7c145-libavformat/movenc.c-mov_write_trailer CVE-2020-22016
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtrack_6713, ExprStmt target_3, NotExpr target_4) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6713
		and target_0.getAnOperand().(Literal).getValue()="64"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6713
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtrack_6713, ExprStmt target_5) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6713
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6713
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="64"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vtrack_6713, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="vos_len"
		and target_2.getQualifier().(VariableAccess).getTarget()=vtrack_6713
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
}

predicate func_3(Variable vtrack_6713, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6713
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6713
}

predicate func_4(Variable vtrack_6713, NotExpr target_4) {
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6713
}

predicate func_5(Variable vtrack_6713, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6713
		and target_5.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="extradata"
		and target_5.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_5.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6713
}

from Function func, Variable vtrack_6713, PointerFieldAccess target_2, ExprStmt target_3, NotExpr target_4, ExprStmt target_5
where
not func_0(vtrack_6713, target_3, target_4)
and not func_1(vtrack_6713, target_5)
and func_2(vtrack_6713, target_2)
and func_3(vtrack_6713, target_3)
and func_4(vtrack_6713, target_4)
and func_5(vtrack_6713, target_5)
and vtrack_6713.getType().hasName("MOVTrack *")
and vtrack_6713.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
