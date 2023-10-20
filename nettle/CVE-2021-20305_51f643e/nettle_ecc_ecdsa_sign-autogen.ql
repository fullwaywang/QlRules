/**
 * @name nettle-51f643eee00e2caa65c8a2f5857f49acdf3ef1ce-nettle_ecc_ecdsa_sign
 * @id cpp/nettle/51f643eee00e2caa65c8a2f5857f49acdf3ef1ce/nettle-ecc-ecdsa-sign
 * @description nettle-51f643eee00e2caa65c8a2f5857f49acdf3ef1ce-ecc-ecdsa-sign.c-nettle_ecc_ecdsa_sign CVE-2021-20305
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vecc_57, Parameter vscratch_64, FunctionCall target_0) {
		target_0.getTarget().hasName("_nettle_ecc_mod_mul")
		and not target_0.getTarget().hasName("_nettle_ecc_mod_mul_canonical")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="q"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_57
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_64
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand() instanceof MulExpr
		and target_0.getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_64
		and target_0.getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_57
		and target_0.getArgument(3).(VariableAccess).getTarget()=vscratch_64
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_64
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_57
}

predicate func_1(Parameter vecc_57, MulExpr target_1) {
		target_1.getLeftOperand().(Literal).getValue()="2"
		and target_1.getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_1.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_1.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_57
}

predicate func_2(Parameter vsp_63, VariableAccess target_2) {
		target_2.getTarget()=vsp_63
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_3(Parameter vscratch_64, PointerArithmeticOperation target_5, VariableAccess target_3) {
		target_3.getTarget()=vscratch_64
		and target_5.getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getLocation())
}

predicate func_4(Parameter vecc_57, Parameter vsp_63, Parameter vscratch_64, Function func, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("__gmpn_copyi")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsp_63
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_64
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_57
		and target_4.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="size"
		and target_4.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_4.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_57
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Parameter vecc_57, Parameter vscratch_64, PointerArithmeticOperation target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget()=vscratch_64
		and target_5.getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_5.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_5.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_5.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_57
}

from Function func, Parameter vecc_57, Parameter vsp_63, Parameter vscratch_64, FunctionCall target_0, MulExpr target_1, VariableAccess target_2, VariableAccess target_3, ExprStmt target_4, PointerArithmeticOperation target_5
where
func_0(vecc_57, vscratch_64, target_0)
and func_1(vecc_57, target_1)
and func_2(vsp_63, target_2)
and func_3(vscratch_64, target_5, target_3)
and func_4(vecc_57, vsp_63, vscratch_64, func, target_4)
and func_5(vecc_57, vscratch_64, target_5)
and vecc_57.getType().hasName("const ecc_curve *")
and vsp_63.getType().hasName("mp_limb_t *")
and vscratch_64.getType().hasName("mp_limb_t *")
and vecc_57.getParentScope+() = func
and vsp_63.getParentScope+() = func
and vscratch_64.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
