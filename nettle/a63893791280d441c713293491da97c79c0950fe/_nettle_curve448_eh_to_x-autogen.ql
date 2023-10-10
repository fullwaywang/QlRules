/**
 * @name nettle-a63893791280d441c713293491da97c79c0950fe-_nettle_curve448_eh_to_x
 * @id cpp/nettle/a63893791280d441c713293491da97c79c0950fe/-nettle-curve448-eh-to-x
 * @description nettle-a63893791280d441c713293491da97c79c0950fe-curve448-eh-to-x.c-_nettle_curve448_eh_to_x CVE-2021-20305
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vscratch_47, Variable vecc_54, FunctionCall target_0) {
		target_0.getTarget().hasName("_nettle_ecc_mod_sqr")
		and not target_0.getTarget().hasName("_nettle_ecc_mod_sqr_canonical")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_54
		and target_0.getArgument(1).(VariableAccess).getTarget()=vscratch_47
		and target_0.getArgument(2).(VariableAccess).getTarget()=vscratch_47
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_47
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_54
}

predicate func_1(Function func, DeclStmt target_1) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vscratch_47, Variable vecc_54, Variable vcy_55, Parameter vxp_47, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcy_55
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__gmpn_sub_n")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vxp_47
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vscratch_47
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="m"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_54
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="size"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_54
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter vscratch_47, Variable vecc_54, Variable vcy_55, Parameter vxp_47, Function func, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("_nettle_cnd_copy")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcy_55
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vxp_47
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vscratch_47
		and target_3.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="size"
		and target_3.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_3.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vecc_54
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

from Function func, Parameter vscratch_47, Variable vecc_54, Variable vcy_55, Parameter vxp_47, FunctionCall target_0, DeclStmt target_1, ExprStmt target_2, ExprStmt target_3
where
func_0(vscratch_47, vecc_54, target_0)
and func_1(func, target_1)
and func_2(vscratch_47, vecc_54, vcy_55, vxp_47, func, target_2)
and func_3(vscratch_47, vecc_54, vcy_55, vxp_47, func, target_3)
and vscratch_47.getType().hasName("mp_limb_t *")
and vecc_54.getType().hasName("const ecc_curve *")
and vcy_55.getType().hasName("mp_limb_t")
and vxp_47.getType().hasName("mp_limb_t *")
and vscratch_47.getParentScope+() = func
and vecc_54.getParentScope+() = func
and vcy_55.getParentScope+() = func
and vxp_47.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
