/**
 * @name ffmpeg-2a7063de547b1d8fb1cef523469390fb59fb2c50-decode_ac_filter
 * @id cpp/ffmpeg/2a7063de547b1d8fb1cef523469390fb59fb2c50/decode-ac-filter
 * @description ffmpeg-2a7063de547b1d8fb1cef523469390fb59fb2c50-libavcodec/wmalosslessdec.c-decode_ac_filter CVE-2012-2795
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_403, ExprStmt target_2, AddressOfExpr target_3) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="acfilter_scaling"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_403
		and target_0.getThen() instanceof FunctionCall
		and target_0.getElse().(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_403, FunctionCall target_1) {
		target_1.getTarget().hasName("get_bits")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_403
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="acfilter_scaling"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_403
}

predicate func_2(Parameter vs_403, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="acfilter_coeffs"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_403
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand() instanceof FunctionCall
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_3(Parameter vs_403, AddressOfExpr target_3) {
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_403
}

from Function func, Parameter vs_403, FunctionCall target_1, ExprStmt target_2, AddressOfExpr target_3
where
not func_0(vs_403, target_2, target_3)
and func_1(vs_403, target_1)
and func_2(vs_403, target_2)
and func_3(vs_403, target_3)
and vs_403.getType().hasName("WmallDecodeCtx *")
and vs_403.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
