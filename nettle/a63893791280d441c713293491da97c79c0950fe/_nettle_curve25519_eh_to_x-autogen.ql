/**
 * @name nettle-a63893791280d441c713293491da97c79c0950fe-_nettle_curve25519_eh_to_x
 * @id cpp/nettle/a63893791280d441c713293491da97c79c0950fe/-nettle-curve25519-eh-to-x
 * @description nettle-a63893791280d441c713293491da97c79c0950fe-curve25519-eh-to-x.c-_nettle_curve25519_eh_to_x CVE-2021-20305
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vscratch_47, Variable vecc_55, FunctionCall target_0) {
		target_0.getTarget().hasName("_nettle_ecc_mod_mul")
		and not target_0.getTarget().hasName("_nettle_ecc_mod_mul_canonical")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_55
		and target_0.getArgument(1).(VariableAccess).getTarget()=vscratch_47
		and target_0.getArgument(2).(VariableAccess).getTarget()=vscratch_47
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_47
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_55
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_47
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_55
}

predicate func_1(Function func, DeclStmt target_1) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vscratch_47, Variable vecc_55, Variable vcy_56, Parameter vxp_46, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcy_56
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__gmpn_sub_n")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vxp_46
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vscratch_47
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="m"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_55
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="size"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_55
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter vscratch_47, Variable vecc_55, Variable vcy_56, Parameter vxp_46, Function func, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("_nettle_cnd_copy")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcy_56
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vxp_46
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vscratch_47
		and target_3.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="size"
		and target_3.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_3.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_55
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

from Function func, Parameter vscratch_47, Variable vecc_55, Variable vcy_56, Parameter vxp_46, FunctionCall target_0, DeclStmt target_1, ExprStmt target_2, ExprStmt target_3
where
func_0(vscratch_47, vecc_55, target_0)
and func_1(func, target_1)
and func_2(vscratch_47, vecc_55, vcy_56, vxp_46, func, target_2)
and func_3(vscratch_47, vecc_55, vcy_56, vxp_46, func, target_3)
and vscratch_47.getType().hasName("mp_limb_t *")
and vecc_55.getType().hasName("const ecc_curve *")
and vcy_56.getType().hasName("mp_limb_t")
and vxp_46.getType().hasName("mp_limb_t *")
and vscratch_47.getParentScope+() = func
and vecc_55.getParentScope+() = func
and vcy_56.getParentScope+() = func
and vxp_46.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
