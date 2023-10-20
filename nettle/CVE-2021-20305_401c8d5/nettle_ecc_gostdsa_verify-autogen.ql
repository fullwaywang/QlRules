/**
 * @name nettle-401c8d53d8a8cf1e79980e62bda3f946f8e07c14-nettle_ecc_gostdsa_verify
 * @id cpp/nettle/401c8d53d8a8cf1e79980e62bda3f946f8e07c14/nettle-ecc-gostdsa-verify
 * @description nettle-401c8d53d8a8cf1e79980e62bda3f946f8e07c14-ecc-gostdsa-verify.c-nettle_ecc_gostdsa_verify CVE-2021-20305
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vecc_61, Parameter vsp_64, Parameter vscratch_65, FunctionCall target_0) {
		target_0.getTarget().hasName("_nettle_ecc_mod_mul")
		and not target_0.getTarget().hasName("_nettle_ecc_mod_mul_canonical")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="q"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_65
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
		and target_0.getArgument(2).(VariableAccess).getTarget()=vsp_64
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_65
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_65
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
}

predicate func_1(Parameter vecc_61, Parameter vrp_64, Parameter vscratch_65, FunctionCall target_1) {
		target_1.getTarget().hasName("_nettle_ecc_mod_mul")
		and not target_1.getTarget().hasName("_nettle_ecc_mod_mul_canonical")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="q"
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_65
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="4"
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
		and target_1.getArgument(2).(VariableAccess).getTarget()=vrp_64
		and target_1.getArgument(3).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_65
		and target_1.getArgument(3).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_1.getArgument(3).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_1.getArgument(3).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_65
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="4"
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
}

predicate func_3(Parameter vecc_61, MulExpr target_3) {
		target_3.getLeftOperand().(Literal).getValue()="4"
		and target_3.getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_3.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_3.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
}

predicate func_4(Parameter vecc_61, Parameter vscratch_65, PointerArithmeticOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vscratch_65
		and target_4.getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="4"
		and target_4.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_4.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_4.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__gmpn_sub_n")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="m"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="q"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="size"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
}

predicate func_5(Parameter vrp_64, VariableAccess target_5) {
		target_5.getTarget()=vrp_64
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Parameter vscratch_65, VariableAccess target_6) {
		target_6.getTarget()=vscratch_65
}

predicate func_7(Parameter vecc_61, Parameter vscratch_65, PointerArithmeticOperation target_8, PointerArithmeticOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vscratch_65
		and target_7.getAnOperand() instanceof MulExpr
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__gmpn_sub_n")
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="m"
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="q"
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof PointerArithmeticOperation
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="size"
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
		and target_8.getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation())
}

predicate func_8(Parameter vecc_61, Parameter vscratch_65, PointerArithmeticOperation target_8) {
		target_8.getAnOperand().(VariableAccess).getTarget()=vscratch_65
		and target_8.getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="4"
		and target_8.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_8.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_8.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_61
}

from Function func, Parameter vecc_61, Parameter vrp_64, Parameter vsp_64, Parameter vscratch_65, FunctionCall target_0, FunctionCall target_1, MulExpr target_3, PointerArithmeticOperation target_4, VariableAccess target_5, VariableAccess target_6, PointerArithmeticOperation target_7, PointerArithmeticOperation target_8
where
func_0(vecc_61, vsp_64, vscratch_65, target_0)
and func_1(vecc_61, vrp_64, vscratch_65, target_1)
and func_3(vecc_61, target_3)
and func_4(vecc_61, vscratch_65, target_4)
and func_5(vrp_64, target_5)
and func_6(vscratch_65, target_6)
and func_7(vecc_61, vscratch_65, target_8, target_7)
and func_8(vecc_61, vscratch_65, target_8)
and vecc_61.getType().hasName("const ecc_curve *")
and vrp_64.getType().hasName("const mp_limb_t *")
and vsp_64.getType().hasName("const mp_limb_t *")
and vscratch_65.getType().hasName("mp_limb_t *")
and vecc_61.getParentScope+() = func
and vrp_64.getParentScope+() = func
and vsp_64.getParentScope+() = func
and vscratch_65.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
