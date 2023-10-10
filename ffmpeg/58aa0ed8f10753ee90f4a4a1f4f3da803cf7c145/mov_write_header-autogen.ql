/**
 * @name ffmpeg-58aa0ed8f10753ee90f4a4a1f4f3da803cf7c145-mov_write_header
 * @id cpp/ffmpeg/58aa0ed8f10753ee90f4a4a1f4f3da803cf7c145/mov-write-header
 * @description ffmpeg-58aa0ed8f10753ee90f4a4a1f4f3da803cf7c145-libavformat/movenc.c-mov_write_header CVE-2020-22016
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtrack_6449, ExprStmt target_3, NotExpr target_4) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6449
		and target_0.getAnOperand().(Literal).getValue()="64"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6449
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtrack_6449, LogicalAndExpr target_5, ExprStmt target_6, LogicalOrExpr target_7) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6449
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6449
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="64"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vtrack_6449, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="vos_len"
		and target_2.getQualifier().(VariableAccess).getTarget()=vtrack_6449
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
}

predicate func_3(Variable vtrack_6449, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6449
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6449
}

predicate func_4(Variable vtrack_6449, NotExpr target_4) {
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6449
}

predicate func_5(Variable vtrack_6449, LogicalAndExpr target_5) {
		target_5.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tag"
		and target_5.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tag"
		and target_5.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6449
		and target_5.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="2021026145"
		and target_5.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tag"
		and target_5.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6449
		and target_5.getAnOperand().(NotExpr).getOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="1852397121"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="codec_id"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codecpar"
}

predicate func_6(Variable vtrack_6449, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vos_data"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6449
		and target_6.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="extradata"
		and target_6.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codecpar"
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="vos_len"
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6449
}

predicate func_7(Variable vtrack_6449, LogicalOrExpr target_7) {
		target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="codec_type"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codecpar"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="channel_layout"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="par"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrack_6449
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
}

from Function func, Variable vtrack_6449, PointerFieldAccess target_2, ExprStmt target_3, NotExpr target_4, LogicalAndExpr target_5, ExprStmt target_6, LogicalOrExpr target_7
where
not func_0(vtrack_6449, target_3, target_4)
and not func_1(vtrack_6449, target_5, target_6, target_7)
and func_2(vtrack_6449, target_2)
and func_3(vtrack_6449, target_3)
and func_4(vtrack_6449, target_4)
and func_5(vtrack_6449, target_5)
and func_6(vtrack_6449, target_6)
and func_7(vtrack_6449, target_7)
and vtrack_6449.getType().hasName("MOVTrack *")
and vtrack_6449.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
