/**
 * @name linux-8b8addf891de8a00e4d39fc32f93f7c5eb8feceb-arch_pick_mmap_layout
 * @id cpp/linux/8b8addf891de8a00e4d39fc32f93f7c5eb8feceb/arch_pick_mmap_layout
 * @description linux-8b8addf891de8a00e4d39fc32f93f7c5eb8feceb-arch_pick_mmap_layout 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vmm_112, Variable vrandom_factor_114) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(ConditionalExpr).getCondition().(FunctionCall).getTarget().hasName("test_ti_thread_flag")
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(ConditionalExpr).getCondition().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("current_thread_info")
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(ConditionalExpr).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="29"
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(ConditionalExpr).getThen().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="personality"
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(ConditionalExpr).getThen().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("get_current")
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(ConditionalExpr).getThen().(ConditionalExpr).getThen().(Literal).getValue()="3221225472"
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(ConditionalExpr).getThen().(ConditionalExpr).getElse().(Literal).getValue()="4294959104"
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="47"
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(ConditionalExpr).getElse().(SubExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getLeftOperand().(ConditionalExpr).getElse().(SubExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(DivExpr).getRightOperand().(Literal).getValue()="3"
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getValue()="4095"
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_0.getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getAnOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="18446744073709547520"
		and target_0.getAnOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getValue()="4095"
		and target_0.getAnOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getAnOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_0.getAnOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getAnOperand().(VariableAccess).getTarget()=vrandom_factor_114
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mmap_legacy_base"
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmm_112)
}

predicate func_2(Variable vrandom_factor_114) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("mmap_legacy_base")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vrandom_factor_114)
}

from Function func, Parameter vmm_112, Variable vrandom_factor_114
where
not func_0(vmm_112, vrandom_factor_114)
and func_2(vrandom_factor_114)
and vmm_112.getType().hasName("mm_struct *")
and vrandom_factor_114.getType().hasName("unsigned long")
and vmm_112.getParentScope+() = func
and vrandom_factor_114.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
