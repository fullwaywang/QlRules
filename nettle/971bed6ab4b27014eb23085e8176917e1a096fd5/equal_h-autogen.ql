/**
 * @name nettle-971bed6ab4b27014eb23085e8176917e1a096fd5-equal_h
 * @id cpp/nettle/971bed6ab4b27014eb23085e8176917e1a096fd5/equal-h
 * @description nettle-971bed6ab4b27014eb23085e8176917e1a096fd5-eddsa-verify.c-equal_h CVE-2021-20305
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_48, Parameter vx1_49, Parameter vz2_50, Parameter vscratch_51, FunctionCall target_0) {
		target_0.getTarget().hasName("_nettle_ecc_mod_mul")
		and not target_0.getTarget().hasName("_nettle_ecc_mod_mul_canonical")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vp_48
		and target_0.getArgument(1).(VariableAccess).getTarget()=vscratch_51
		and target_0.getArgument(2).(VariableAccess).getTarget()=vx1_49
		and target_0.getArgument(3).(VariableAccess).getTarget()=vz2_50
		and target_0.getArgument(4).(VariableAccess).getTarget()=vscratch_51
}

predicate func_1(Parameter vp_48, Parameter vz1_49, Parameter vx2_50, Parameter vscratch_51, FunctionCall target_1) {
		target_1.getTarget().hasName("_nettle_ecc_mod_mul")
		and not target_1.getTarget().hasName("_nettle_ecc_mod_mul_canonical")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vp_48
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_51
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_48
		and target_1.getArgument(2).(VariableAccess).getTarget()=vx2_50
		and target_1.getArgument(3).(VariableAccess).getTarget()=vz1_49
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_51
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_48
}

predicate func_2(Parameter vp_48, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="size"
		and target_2.getQualifier().(VariableAccess).getTarget()=vp_48
		and target_2.getParent().(FunctionCall).getParent().(GEExpr).getGreaterOperand() instanceof FunctionCall
}

predicate func_3(Parameter vp_48, Parameter vscratch_51, PointerArithmeticOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vscratch_51
		and target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_48
		and target_3.getParent().(FunctionCall).getParent().(GEExpr).getGreaterOperand() instanceof FunctionCall
}

predicate func_4(Parameter vp_48, Parameter vscratch_51, Function func, IfStmt target_4) {
		target_4.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("__gmpn_cmp")
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vscratch_51
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="m"
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_48
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="size"
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_48
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__gmpn_sub_n")
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vscratch_51
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vscratch_51
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="m"
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_48
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="size"
		and target_4.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_48
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Parameter vp_48, Parameter vscratch_51, Function func, IfStmt target_5) {
		target_5.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("__gmpn_cmp")
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="m"
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_48
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="size"
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_48
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__gmpn_sub_n")
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_51
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_48
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_51
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_48
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="m"
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_48
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="size"
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_48
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

from Function func, Parameter vp_48, Parameter vx1_49, Parameter vz1_49, Parameter vx2_50, Parameter vz2_50, Parameter vscratch_51, FunctionCall target_0, FunctionCall target_1, PointerFieldAccess target_2, PointerArithmeticOperation target_3, IfStmt target_4, IfStmt target_5
where
func_0(vp_48, vx1_49, vz2_50, vscratch_51, target_0)
and func_1(vp_48, vz1_49, vx2_50, vscratch_51, target_1)
and func_2(vp_48, target_2)
and func_3(vp_48, vscratch_51, target_3)
and func_4(vp_48, vscratch_51, func, target_4)
and func_5(vp_48, vscratch_51, func, target_5)
and vp_48.getType().hasName("const ecc_modulo *")
and vx1_49.getType().hasName("const mp_limb_t *")
and vz1_49.getType().hasName("const mp_limb_t *")
and vx2_50.getType().hasName("const mp_limb_t *")
and vz2_50.getType().hasName("const mp_limb_t *")
and vscratch_51.getType().hasName("mp_limb_t *")
and vp_48.getParentScope+() = func
and vx1_49.getParentScope+() = func
and vz1_49.getParentScope+() = func
and vx2_50.getParentScope+() = func
and vz2_50.getParentScope+() = func
and vscratch_51.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
