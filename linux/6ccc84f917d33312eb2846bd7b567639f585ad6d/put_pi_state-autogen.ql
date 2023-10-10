/**
 * @name linux-6ccc84f917d33312eb2846bd7b567639f585ad6d-put_pi_state
 * @id cpp/linux/6ccc84f917d33312eb2846bd7b567639f585ad6d/put_pi_state
 * @description linux-6ccc84f917d33312eb2846bd7b567639f585ad6d-put_pi_state 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("_raw_spin_lock")
		and not target_0.getTarget().hasName("pi_state_update_owner")
		and target_0.getArgument(0).(AddressOfExpr).getOperand() instanceof PointerFieldAccess
		and target_0.getEnclosingFunction() = func)
}

predicate func_3(Parameter vpi_state_798) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="owner"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_state_798)
}

predicate func_4(Parameter vpi_state_798, Variable vowner_811) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=vowner_811
		and target_4.getRValue().(PointerFieldAccess).getTarget().getName()="owner"
		and target_4.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_state_798)
}

predicate func_5(Parameter vpi_state_798, Variable vowner_811) {
	exists(IfStmt target_5 |
		target_5.getCondition().(VariableAccess).getTarget()=vowner_811
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("list_del_init")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="list"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_state_798
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_raw_spin_unlock")
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_lock"
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vowner_811
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="owner"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_state_798)
}

predicate func_7(Variable vowner_811) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="pi_lock"
		and target_7.getQualifier().(VariableAccess).getTarget()=vowner_811)
}

from Function func, Parameter vpi_state_798, Variable vowner_811
where
func_0(func)
and func_3(vpi_state_798)
and func_4(vpi_state_798, vowner_811)
and func_5(vpi_state_798, vowner_811)
and func_7(vowner_811)
and vpi_state_798.getType().hasName("futex_pi_state *")
and vowner_811.getType().hasName("task_struct *")
and vpi_state_798.getParentScope+() = func
and vowner_811.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
