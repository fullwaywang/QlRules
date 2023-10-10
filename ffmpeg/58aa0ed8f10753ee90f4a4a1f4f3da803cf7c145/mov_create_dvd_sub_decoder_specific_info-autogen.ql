/**
 * @name ffmpeg-58aa0ed8f10753ee90f4a4a1f4f3da803cf7c145-mov_create_dvd_sub_decoder_specific_info
 * @id cpp/ffmpeg/58aa0ed8f10753ee90f4a4a1f4f3da803cf7c145/mov-create-dvd-sub-decoder-specific-info
 * @description ffmpeg-58aa0ed8f10753ee90f4a4a1f4f3da803cf7c145-libavformat/movenc.c-mov_create_dvd_sub_decoder_specific_info CVE-2020-22016
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AddExpr target_0 |
		target_0.getValue()="128"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof MulExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vtrack_6059, VariableAccess target_3, PointerArithmeticOperation target_4, ExprStmt target_5) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6059
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getValue()="64"
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="64"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Function func, MulExpr target_2) {
		target_2.getValue()="64"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vhave_palette_6063, VariableAccess target_3) {
		target_3.getTarget()=vhave_palette_6063
}

predicate func_4(Parameter vtrack_6059, PointerArithmeticOperation target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6059
		and target_4.getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="4"
}

predicate func_5(Parameter vtrack_6059, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6059
		and target_5.getExpr().(AssignExpr).getRValue().(MulExpr).getValue()="64"
}

from Function func, Variable vhave_palette_6063, Parameter vtrack_6059, MulExpr target_2, VariableAccess target_3, PointerArithmeticOperation target_4, ExprStmt target_5
where
not func_0(func)
and not func_1(vtrack_6059, target_3, target_4, target_5)
and func_2(func, target_2)
and func_3(vhave_palette_6063, target_3)
and func_4(vtrack_6059, target_4)
and func_5(vtrack_6059, target_5)
and vhave_palette_6063.getType().hasName("int")
and vtrack_6059.getType().hasName("MOVTrack *")
and vhave_palette_6063.getParentScope+() = func
and vtrack_6059.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
