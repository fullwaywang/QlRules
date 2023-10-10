/**
 * @name libtiff-5c080298d59efa53264d7248bbe3a04660db6ef7-pickCopyFunc
 * @id cpp/libtiff/5c080298d59efa53264d7248bbe3a04660db6ef7/pickCopyFunc
 * @description libtiff-5c080298d59efa53264d7248bbe3a04660db6ef7-tools/tiffcp.c-pickCopyFunc CVE-2017-5225
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vshortv_1783, Parameter vin_1781, FunctionCall target_0) {
		target_0.getTarget().hasName("TIFFGetField")
		and not target_0.getTarget().hasName("TIFFGetFieldDefaulted")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vin_1781
		and target_0.getArgument(1).(Literal).getValue()="284"
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vshortv_1783
}

from Function func, Variable vshortv_1783, Parameter vin_1781, FunctionCall target_0
where
func_0(vshortv_1783, vin_1781, target_0)
and vshortv_1783.getType().hasName("uint16")
and vin_1781.getType().hasName("TIFF *")
and vshortv_1783.(LocalVariable).getFunction() = func
and vin_1781.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
