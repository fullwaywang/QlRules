/**
 * @name nettle-a63893791280d441c713293491da97c79c0950fe-_nettle_ecc_j_to_a
 * @id cpp/nettle/a63893791280d441c713293491da97c79c0950fe/-nettle-ecc-j-to-a
 * @description nettle-a63893791280d441c713293491da97c79c0950fe-ecc-j-to-a.c-_nettle_ecc_j_to_a CVE-2021-20305
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vecc_42, Parameter vp_44, Parameter vscratch_45, FunctionCall target_0) {
		target_0.getTarget().hasName("_nettle_ecc_mod_mul")
		and not target_0.getTarget().hasName("_nettle_ecc_mod_mul_canonical")
		and target_0.getArgument(0) instanceof AddressOfExpr
		and target_0.getArgument(1) instanceof PointerArithmeticOperation
		and target_0.getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_45
		and target_0.getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(2).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
		and target_0.getArgument(3).(VariableAccess).getTarget()=vp_44
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_45
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
}

predicate func_1(Parameter vr_44, Parameter vscratch_45, Variable vcy_52, FunctionCall target_1) {
		target_1.getTarget().hasName("_nettle_cnd_copy")
		and not target_1.getTarget().hasName("_nettle_ecc_mod_mul_canonical")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vcy_52
		and target_1.getArgument(1).(VariableAccess).getTarget()=vr_44
		and target_1.getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_45
		and target_1.getArgument(2).(PointerArithmeticOperation).getAnOperand() instanceof MulExpr
		and target_1.getArgument(3) instanceof ValueFieldAccess
}

predicate func_3(Function func, DeclStmt target_3) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Parameter vecc_42, AddressOfExpr target_4) {
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_5(Parameter vecc_42, Parameter vscratch_45, PointerArithmeticOperation target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget()=vscratch_45
		and target_5.getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_5.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_5.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_5.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Parameter vecc_42, MulExpr target_6) {
		target_6.getLeftOperand().(Literal).getValue()="2"
		and target_6.getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_6.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_6.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
}

predicate func_7(Parameter vecc_42, ValueFieldAccess target_7) {
		target_7.getTarget().getName()="size"
		and target_7.getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
}

predicate func_8(Parameter vecc_42, MulExpr target_8) {
		target_8.getLeftOperand().(Literal).getValue()="2"
		and target_8.getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_8.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_8.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
}

predicate func_9(Parameter vecc_42, ValueFieldAccess target_9) {
		target_9.getTarget().getName()="size"
		and target_9.getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
}

predicate func_10(Parameter vecc_42, Parameter vscratch_45, PointerArithmeticOperation target_10) {
		target_10.getAnOperand().(VariableAccess).getTarget()=vscratch_45
		and target_10.getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_10.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_10.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_10.getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_11(Parameter vecc_42, Parameter vp_44, PointerArithmeticOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vp_44
		and target_11.getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_11.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_11.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_12(Parameter vecc_42, PointerFieldAccess target_12) {
		target_12.getTarget().getName()="p"
		and target_12.getQualifier().(VariableAccess).getTarget()=vecc_42
}

predicate func_13(Parameter vecc_42, AddressOfExpr target_13) {
		target_13.getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_13.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_14(Parameter vecc_42, Parameter vr_44, PointerArithmeticOperation target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vr_44
		and target_14.getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_14.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_14.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
		and target_14.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_15(Parameter vr_44, VariableAccess target_15) {
		target_15.getTarget()=vr_44
		and target_15.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_16(Parameter vscratch_45, VariableAccess target_16) {
		target_16.getTarget()=vscratch_45
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_17(Parameter vecc_42, Parameter vr_44, Parameter vscratch_45, Variable vcy_52, AssignExpr target_17) {
		target_17.getLValue().(VariableAccess).getTarget()=vcy_52
		and target_17.getRValue().(FunctionCall).getTarget().hasName("__gmpn_sub_n")
		and target_17.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_44
		and target_17.getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_45
		and target_17.getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand() instanceof MulExpr
		and target_17.getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="m"
		and target_17.getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_17.getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
		and target_17.getRValue().(FunctionCall).getArgument(3) instanceof ValueFieldAccess
}

predicate func_18(Function func, ExprStmt target_18) {
		target_18.getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18
}

predicate func_19(Parameter vscratch_45, PointerArithmeticOperation target_24, ExprStmt target_25, VariableAccess target_19) {
		target_19.getTarget()=vscratch_45
		and target_24.getAnOperand().(VariableAccess).getLocation().isBefore(target_19.getLocation())
		and target_19.getLocation().isBefore(target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_20(Parameter vscratch_45, Function func, ExprStmt target_20) {
		target_20.getExpr().(FunctionCall).getTarget().hasName("_nettle_ecc_mod_mul")
		and target_20.getExpr().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_20.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vscratch_45
		and target_20.getExpr().(FunctionCall).getArgument(2) instanceof PointerArithmeticOperation
		and target_20.getExpr().(FunctionCall).getArgument(3) instanceof PointerArithmeticOperation
		and target_20.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vscratch_45
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_20
}

predicate func_21(Parameter vecc_42, Parameter vscratch_45, Variable vcy_52, Function func, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcy_52
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__gmpn_sub_n")
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vscratch_45
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="m"
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="size"
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_21
}

predicate func_22(Parameter vecc_42, Parameter vr_44, Parameter vscratch_45, Variable vcy_52, Function func, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("_nettle_cnd_copy")
		and target_22.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcy_52
		and target_22.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vr_44
		and target_22.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_22.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_22.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
		and target_22.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vscratch_45
		and target_22.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="size"
		and target_22.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_22.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_22
}

predicate func_24(Parameter vscratch_45, PointerArithmeticOperation target_24) {
		target_24.getAnOperand().(VariableAccess).getTarget()=vscratch_45
		and target_24.getAnOperand() instanceof MulExpr
}

predicate func_25(Parameter vecc_42, Parameter vr_44, Parameter vscratch_45, Variable vcy_52, ExprStmt target_25) {
		target_25.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcy_52
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__gmpn_sub_n")
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vscratch_45
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vr_44
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="m"
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="q"
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="size"
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_42
}

from Function func, Parameter vecc_42, Parameter vr_44, Parameter vp_44, Parameter vscratch_45, Variable vcy_52, FunctionCall target_0, FunctionCall target_1, DeclStmt target_3, AddressOfExpr target_4, PointerArithmeticOperation target_5, MulExpr target_6, ValueFieldAccess target_7, MulExpr target_8, ValueFieldAccess target_9, PointerArithmeticOperation target_10, PointerArithmeticOperation target_11, PointerFieldAccess target_12, AddressOfExpr target_13, PointerArithmeticOperation target_14, VariableAccess target_15, VariableAccess target_16, AssignExpr target_17, ExprStmt target_18, VariableAccess target_19, ExprStmt target_20, ExprStmt target_21, ExprStmt target_22, PointerArithmeticOperation target_24, ExprStmt target_25
where
func_0(vecc_42, vp_44, vscratch_45, target_0)
and func_1(vr_44, vscratch_45, vcy_52, target_1)
and func_3(func, target_3)
and func_4(vecc_42, target_4)
and func_5(vecc_42, vscratch_45, target_5)
and func_6(vecc_42, target_6)
and func_7(vecc_42, target_7)
and func_8(vecc_42, target_8)
and func_9(vecc_42, target_9)
and func_10(vecc_42, vscratch_45, target_10)
and func_11(vecc_42, vp_44, target_11)
and func_12(vecc_42, target_12)
and func_13(vecc_42, target_13)
and func_14(vecc_42, vr_44, target_14)
and func_15(vr_44, target_15)
and func_16(vscratch_45, target_16)
and func_17(vecc_42, vr_44, vscratch_45, vcy_52, target_17)
and func_18(func, target_18)
and func_19(vscratch_45, target_24, target_25, target_19)
and func_20(vscratch_45, func, target_20)
and func_21(vecc_42, vscratch_45, vcy_52, func, target_21)
and func_22(vecc_42, vr_44, vscratch_45, vcy_52, func, target_22)
and func_24(vscratch_45, target_24)
and func_25(vecc_42, vr_44, vscratch_45, vcy_52, target_25)
and vecc_42.getType().hasName("const ecc_curve *")
and vr_44.getType().hasName("mp_limb_t *")
and vp_44.getType().hasName("const mp_limb_t *")
and vscratch_45.getType().hasName("mp_limb_t *")
and vcy_52.getType().hasName("mp_limb_t")
and vecc_42.getParentScope+() = func
and vr_44.getParentScope+() = func
and vp_44.getParentScope+() = func
and vscratch_45.getParentScope+() = func
and vcy_52.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
