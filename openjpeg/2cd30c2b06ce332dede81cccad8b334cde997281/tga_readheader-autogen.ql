/**
 * @name openjpeg-2cd30c2b06ce332dede81cccad8b334cde997281-tga_readheader
 * @id cpp/openjpeg/2cd30c2b06ce332dede81cccad8b334cde997281/tga-readheader
 * @description openjpeg-2cd30c2b06ce332dede81cccad8b334cde997281-src/bin/jp2/convert.c-tga_readheader CVE-2017-14040
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtga_598, FunctionCall target_0) {
		target_0.getTarget().hasName("get_ushort")
		and not target_0.getTarget().hasName("get_tga_ushort")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtga_598
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="5"
}

predicate func_1(Variable vtga_598, FunctionCall target_1) {
		target_1.getTarget().hasName("get_ushort")
		and not target_1.getTarget().hasName("get_tga_ushort")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtga_598
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="12"
}

predicate func_2(Variable vtga_598, FunctionCall target_2) {
		target_2.getTarget().hasName("get_ushort")
		and not target_2.getTarget().hasName("get_tga_ushort")
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtga_598
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="14"
}

from Function func, Variable vtga_598, FunctionCall target_0, FunctionCall target_1, FunctionCall target_2
where
func_0(vtga_598, target_0)
and func_1(vtga_598, target_1)
and func_2(vtga_598, target_2)
and vtga_598.getType().hasName("unsigned char[18]")
and vtga_598.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
