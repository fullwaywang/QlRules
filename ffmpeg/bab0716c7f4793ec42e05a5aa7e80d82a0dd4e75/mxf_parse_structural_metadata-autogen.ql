/**
 * @name ffmpeg-bab0716c7f4793ec42e05a5aa7e80d82a0dd4e75-mxf_parse_structural_metadata
 * @id cpp/ffmpeg/bab0716c7f4793ec42e05a5aa7e80d82a0dd4e75/mxf-parse-structural-metadata
 * @description ffmpeg-bab0716c7f4793ec42e05a5aa7e80d82a0dd4e75-libavformat/mxfdec.c-mxf_parse_structural_metadata CVE-2018-1999014
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmxf_2055, AddressOfExpr target_2, AssignExpr target_3) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="fc"
		and target_0.getQualifier().(VariableAccess).getTarget()=vmxf_2055
		and target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation())
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vmxf_2055, VariableAccess target_1) {
		target_1.getTarget()=vmxf_2055
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="56"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="could not resolve essence container data strong ref\n"
}

predicate func_2(Parameter vmxf_2055, AddressOfExpr target_2) {
		target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="essence_container_data_refs"
		and target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmxf_2055
}

predicate func_3(Parameter vmxf_2055, AssignExpr target_3) {
		target_3.getRValue().(FunctionCall).getTarget().hasName("mxf_add_metadata_stream")
		and target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmxf_2055
}

from Function func, Parameter vmxf_2055, VariableAccess target_1, AddressOfExpr target_2, AssignExpr target_3
where
not func_0(vmxf_2055, target_2, target_3)
and func_1(vmxf_2055, target_1)
and func_2(vmxf_2055, target_2)
and func_3(vmxf_2055, target_3)
and vmxf_2055.getType().hasName("MXFContext *")
and vmxf_2055.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
