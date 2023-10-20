/**
 * @name nettle-74ee0e82b6891e090f20723750faeb19064e31b2-nettle_ecc_ecdsa_verify
 * @id cpp/nettle/74ee0e82b6891e090f20723750faeb19064e31b2/nettle-ecc-ecdsa-verify
 * @description nettle-74ee0e82b6891e090f20723750faeb19064e31b2-ecc-ecdsa-verify.c-nettle_ecc_ecdsa_verify CVE-2021-20305
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vecc_62, Parameter vscratch_66, FunctionCall target_0) {
		target_0.getTarget().hasName("_nettle_ecc_mod_mul")
		and not target_0.getTarget().hasName("_nettle_ecc_mod_mul_canonical")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="q"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_62
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_66
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_62
		and target_0.getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_66
		and target_0.getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_62
		and target_0.getArgument(3).(VariableAccess).getTarget()=vscratch_66
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_66
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_62
}

predicate func_1(Parameter vecc_62, Parameter vrp_65, Parameter vscratch_66, FunctionCall target_1) {
		target_1.getTarget().hasName("_nettle_ecc_mod_mul")
		and not target_1.getTarget().hasName("_nettle_ecc_mod_mul_canonical")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="q"
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_62
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_66
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="4"
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_62
		and target_1.getArgument(2).(VariableAccess).getTarget()=vrp_65
		and target_1.getArgument(3).(VariableAccess).getTarget()=vscratch_66
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_66
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="4"
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_62
}

from Function func, Parameter vecc_62, Parameter vrp_65, Parameter vscratch_66, FunctionCall target_0, FunctionCall target_1
where
func_0(vecc_62, vscratch_66, target_0)
and func_1(vecc_62, vrp_65, vscratch_66, target_1)
and vecc_62.getType().hasName("const ecc_curve *")
and vrp_65.getType().hasName("const mp_limb_t *")
and vscratch_66.getType().hasName("mp_limb_t *")
and vecc_62.getParentScope+() = func
and vrp_65.getParentScope+() = func
and vscratch_66.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
