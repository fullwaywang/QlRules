/**
 * @name nettle-ae3801a0e5cce276c270973214385c86048d5f7b-_nettle_eddsa_hash
 * @id cpp/nettle/ae3801a0e5cce276c270973214385c86048d5f7b/-nettle-eddsa-hash
 * @description nettle-ae3801a0e5cce276c270973214385c86048d5f7b-eddsa-hash.c-_nettle_eddsa_hash CVE-2021-20305
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vm_50, Parameter vrp_51, ExprStmt target_4) {
	exists(PointerArithmeticOperation target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vrp_51
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_50
		and target_0.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="mod"
		and target_0.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_50
		and target_0.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vm_50
		and target_0.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vrp_51
		and target_0.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vrp_51
		and target_4.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vm_50, Parameter vrp_51, ExprStmt target_4, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("mp_limb_t")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__gmpn_sub_n")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrp_51
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrp_51
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_50
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="m"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_50
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_50
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1)
		and target_4.getExpr().(VariableCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vm_50, Parameter vrp_51, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("_nettle_cnd_copy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("mp_limb_t")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrp_51
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrp_51
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_50
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="size"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_50
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vm_50, Parameter vrp_51, VariableAccess target_3) {
		target_3.getTarget()=vrp_51
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="mod"
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_50
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vm_50
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vrp_51
}

predicate func_4(Parameter vm_50, Parameter vrp_51, ExprStmt target_4) {
		target_4.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="mod"
		and target_4.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_50
		and target_4.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vm_50
		and target_4.getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vrp_51
		and target_4.getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vrp_51
}

from Function func, Parameter vm_50, Parameter vrp_51, VariableAccess target_3, ExprStmt target_4
where
not func_0(vm_50, vrp_51, target_4)
and not func_1(vm_50, vrp_51, target_4, func)
and not func_2(vm_50, vrp_51, func)
and func_3(vm_50, vrp_51, target_3)
and func_4(vm_50, vrp_51, target_4)
and vm_50.getType().hasName("const ecc_modulo *")
and vrp_51.getType().hasName("mp_limb_t *")
and vm_50.getParentScope+() = func
and vrp_51.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
