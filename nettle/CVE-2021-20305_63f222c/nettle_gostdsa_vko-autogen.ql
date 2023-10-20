/**
 * @name nettle-63f222c60b03470c0005aa9bc4296fbf585f68b9-nettle_gostdsa_vko
 * @id cpp/nettle/63f222c60b03470c0005aa9bc4296fbf585f68b9/nettle-gostdsa-vko
 * @description nettle-63f222c60b03470c0005aa9bc4296fbf585f68b9-gostdsa-vko.c-nettle_gostdsa_vko CVE-2021-20305
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vecc_62, Variable vsize_64, Variable vscratch_66, Parameter vpriv_57, FunctionCall target_0) {
		target_0.getTarget().hasName("_nettle_ecc_mod_mul")
		and not target_0.getTarget().hasName("_nettle_ecc_mod_mul_canonical")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="q"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_62
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_66
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vsize_64
		and target_0.getArgument(2).(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpriv_57
		and target_0.getArgument(3).(VariableAccess).getTarget()=vscratch_66
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_66
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vsize_64
}

from Function func, Variable vecc_62, Variable vsize_64, Variable vscratch_66, Parameter vpriv_57, FunctionCall target_0
where
func_0(vecc_62, vsize_64, vscratch_66, vpriv_57, target_0)
and vecc_62.getType().hasName("const ecc_curve *")
and vsize_64.getType().hasName("mp_size_t")
and vscratch_66.getType().hasName("mp_limb_t *")
and vpriv_57.getType().hasName("const ecc_scalar *")
and vecc_62.getParentScope+() = func
and vsize_64.getParentScope+() = func
and vscratch_66.getParentScope+() = func
and vpriv_57.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
