/**
 * @name tpm2-tss-306490c8d848c367faa2d9df81f5e69dab46ffb5-unknown_layer_handler
 * @id cpp/tpm2-tss/306490c8d848c367faa2d9df81f5e69dab46ffb5/unknown-layer-handler
 * @description tpm2-tss-306490c8d848c367faa2d9df81f5e69dab46ffb5-src/tss2-rc/tss2_rc.c-unknown_layer_handler CVE-2023-22745
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrc_879, VariableAccess target_0) {
		target_0.getTarget()=vrc_879
		and target_0.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(3) instanceof FunctionCall
}

predicate func_1(Parameter vrc_879, FunctionCall target_1) {
		target_1.getTarget().hasName("tpm2_error_get")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vrc_879
}

from Function func, Parameter vrc_879, VariableAccess target_0, FunctionCall target_1
where
func_0(vrc_879, target_0)
and func_1(vrc_879, target_1)
and vrc_879.getType().hasName("TSS2_RC")
and vrc_879.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
