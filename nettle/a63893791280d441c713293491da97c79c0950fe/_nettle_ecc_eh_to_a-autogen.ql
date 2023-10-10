/**
 * @name nettle-a63893791280d441c713293491da97c79c0950fe-_nettle_ecc_eh_to_a
 * @id cpp/nettle/a63893791280d441c713293491da97c79c0950fe/-nettle-ecc-eh-to-a
 * @description nettle-a63893791280d441c713293491da97c79c0950fe-ecc-eh-to-a.c-_nettle_ecc_eh_to_a CVE-2021-20305
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_0(Parameter vscratch_47, PointerArithmeticOperation target_17, VariableAccess target_0) {
		target_0.getTarget()=vscratch_47
		and target_17.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getLocation())
}

*/
predicate func_1(Parameter vecc_44, Parameter vp_46, Parameter vscratch_47, FunctionCall target_1) {
		target_1.getTarget().hasName("_nettle_ecc_mod_mul")
		and not target_1.getTarget().hasName("_nettle_ecc_mod_mul_canonical")
		and target_1.getArgument(0) instanceof AddressOfExpr
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_47
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
		and target_1.getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_46
		and target_1.getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_1.getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_1.getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
		and target_1.getArgument(3).(VariableAccess).getTarget()=vscratch_47
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_47
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_1.getArgument(4).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
}

predicate func_2(Parameter vecc_44, Parameter vp_46, Parameter vscratch_47, FunctionCall target_2) {
		target_2.getTarget().hasName("_nettle_ecc_mod_mul")
		and not target_2.getTarget().hasName("_nettle_ecc_mod_mul_canonical")
		and target_2.getArgument(0) instanceof AddressOfExpr
		and target_2.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_47
		and target_2.getArgument(1).(PointerArithmeticOperation).getAnOperand() instanceof ValueFieldAccess
		and target_2.getArgument(2).(VariableAccess).getTarget()=vp_46
		and target_2.getArgument(3).(VariableAccess).getTarget()=vscratch_47
		and target_2.getArgument(4).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_47
		and target_2.getArgument(4).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_2.getArgument(4).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_2.getArgument(4).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
}

predicate func_3(Parameter vecc_44, AddressOfExpr target_3) {
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_4(Parameter vecc_44, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="size"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
}

predicate func_5(Parameter vecc_44, ValueFieldAccess target_5) {
		target_5.getTarget().getName()="size"
		and target_5.getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
}

predicate func_6(Parameter vecc_44, ValueFieldAccess target_6) {
		target_6.getTarget().getName()="size"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
}

predicate func_7(Parameter vecc_44, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="p"
		and target_7.getQualifier().(VariableAccess).getTarget()=vecc_44
}

predicate func_8(Parameter vecc_44, AddressOfExpr target_8) {
		target_8.getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_8.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_9(Parameter vecc_44, Parameter vr_46, PointerArithmeticOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vr_46
		and target_9.getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_9.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_9.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_10(Parameter vr_46, VariableAccess target_10) {
		target_10.getTarget()=vr_46
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_11(Function func, DeclStmt target_11) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

predicate func_12(Parameter vscratch_47, PointerArithmeticOperation target_18, VariableAccess target_12) {
		target_12.getTarget()=vscratch_47
		and target_18.getAnOperand().(VariableAccess).getLocation().isBefore(target_12.getLocation())
}

predicate func_13(Parameter vecc_44, Parameter vr_46, Parameter vscratch_47, Variable vcy_57, Function func, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcy_57
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__gmpn_sub_n")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_46
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_47
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand() instanceof ValueFieldAccess
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="m"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="size"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13
}

predicate func_14(Parameter vecc_44, Parameter vr_46, Parameter vscratch_47, Variable vcy_57, Function func, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("_nettle_cnd_copy")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcy_57
		and target_14.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vr_46
		and target_14.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_47
		and target_14.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand() instanceof ValueFieldAccess
		and target_14.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="size"
		and target_14.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_14.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Parameter vecc_44, Parameter vscratch_47, Variable vcy_57, Function func, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcy_57
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__gmpn_sub_n")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_47
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="m"
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="size"
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_15
}

predicate func_16(Parameter vecc_44, Parameter vr_46, Parameter vscratch_47, Variable vcy_57, Function func, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("_nettle_cnd_copy")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcy_57
		and target_16.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vr_46
		and target_16.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_16.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_16.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_47
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
		and target_16.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="size"
		and target_16.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_16.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_16
}

predicate func_17(Parameter vscratch_47, PointerArithmeticOperation target_17) {
		target_17.getAnOperand().(VariableAccess).getTarget()=vscratch_47
		and target_17.getAnOperand() instanceof ValueFieldAccess
}

predicate func_18(Parameter vecc_44, Parameter vscratch_47, PointerArithmeticOperation target_18) {
		target_18.getAnOperand().(VariableAccess).getTarget()=vscratch_47
		and target_18.getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_18.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_18.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_44
}

from Function func, Parameter vecc_44, Parameter vr_46, Parameter vp_46, Parameter vscratch_47, Variable vcy_57, FunctionCall target_1, FunctionCall target_2, AddressOfExpr target_3, ValueFieldAccess target_4, ValueFieldAccess target_5, ValueFieldAccess target_6, PointerFieldAccess target_7, AddressOfExpr target_8, PointerArithmeticOperation target_9, VariableAccess target_10, DeclStmt target_11, VariableAccess target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, PointerArithmeticOperation target_17, PointerArithmeticOperation target_18
where
func_1(vecc_44, vp_46, vscratch_47, target_1)
and func_2(vecc_44, vp_46, vscratch_47, target_2)
and func_3(vecc_44, target_3)
and func_4(vecc_44, target_4)
and func_5(vecc_44, target_5)
and func_6(vecc_44, target_6)
and func_7(vecc_44, target_7)
and func_8(vecc_44, target_8)
and func_9(vecc_44, vr_46, target_9)
and func_10(vr_46, target_10)
and func_11(func, target_11)
and func_12(vscratch_47, target_18, target_12)
and func_13(vecc_44, vr_46, vscratch_47, vcy_57, func, target_13)
and func_14(vecc_44, vr_46, vscratch_47, vcy_57, func, target_14)
and func_15(vecc_44, vscratch_47, vcy_57, func, target_15)
and func_16(vecc_44, vr_46, vscratch_47, vcy_57, func, target_16)
and func_17(vscratch_47, target_17)
and func_18(vecc_44, vscratch_47, target_18)
and vecc_44.getType().hasName("const ecc_curve *")
and vr_46.getType().hasName("mp_limb_t *")
and vp_46.getType().hasName("const mp_limb_t *")
and vscratch_47.getType().hasName("mp_limb_t *")
and vcy_57.getType().hasName("mp_limb_t")
and vecc_44.getParentScope+() = func
and vr_46.getParentScope+() = func
and vp_46.getParentScope+() = func
and vscratch_47.getParentScope+() = func
and vcy_57.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
