/**
 * @name nettle-a63893791280d441c713293491da97c79c0950fe-_nettle_ecc_mul_m
 * @id cpp/nettle/a63893791280d441c713293491da97c79c0950fe/-nettle-ecc-mul-m
 * @description nettle-a63893791280d441c713293491da97c79c0950fe-ecc-mul-m.c-_nettle_ecc_mul_m CVE-2021-20305
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vscratch_48, Parameter vm_44, FunctionCall target_0) {
		target_0.getTarget().hasName("_nettle_ecc_mod_mul")
		and not target_0.getTarget().hasName("_nettle_ecc_mod_mul_canonical")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vm_44
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_48
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand() instanceof MulExpr
		and target_0.getArgument(2).(VariableAccess).getTarget()=vscratch_48
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_48
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(3).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_44
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_48
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_0.getArgument(4).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_44
}

predicate func_1(Parameter vm_44, MulExpr target_1) {
		target_1.getLeftOperand().(Literal).getValue()="3"
		and target_1.getRightOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_44
}

predicate func_2(Parameter vqx_47, VariableAccess target_2) {
		target_2.getTarget()=vqx_47
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_4(Parameter vscratch_48, PointerArithmeticOperation target_7, VariableAccess target_4) {
		target_4.getTarget()=vscratch_48
		and target_7.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getLocation())
}

predicate func_5(Parameter vqx_47, Parameter vscratch_48, Variable vcy_51, Parameter vm_44, Function func, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcy_51
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__gmpn_sub_n")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vqx_47
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_48
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_44
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="m"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_44
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="size"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_44
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Parameter vqx_47, Parameter vscratch_48, Variable vcy_51, Parameter vm_44, Function func, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("_nettle_cnd_copy")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcy_51
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vqx_47
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_48
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_44
		and target_6.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="size"
		and target_6.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_44
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Parameter vscratch_48, Parameter vm_44, PointerArithmeticOperation target_7) {
		target_7.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vscratch_48
		and target_7.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_7.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_7.getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_44
		and target_7.getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_7.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_44
}

from Function func, Parameter vqx_47, Parameter vscratch_48, Variable vcy_51, Parameter vm_44, FunctionCall target_0, MulExpr target_1, VariableAccess target_2, VariableAccess target_4, ExprStmt target_5, ExprStmt target_6, PointerArithmeticOperation target_7
where
func_0(vscratch_48, vm_44, target_0)
and func_1(vm_44, target_1)
and func_2(vqx_47, target_2)
and func_4(vscratch_48, target_7, target_4)
and func_5(vqx_47, vscratch_48, vcy_51, vm_44, func, target_5)
and func_6(vqx_47, vscratch_48, vcy_51, vm_44, func, target_6)
and func_7(vscratch_48, vm_44, target_7)
and vqx_47.getType().hasName("mp_limb_t *")
and vscratch_48.getType().hasName("mp_limb_t *")
and vcy_51.getType().hasName("mp_limb_t")
and vm_44.getType().hasName("const ecc_modulo *")
and vqx_47.getParentScope+() = func
and vscratch_48.getParentScope+() = func
and vcy_51.getParentScope+() = func
and vm_44.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
