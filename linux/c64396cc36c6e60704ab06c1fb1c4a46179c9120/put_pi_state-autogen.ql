/**
 * @name linux-c64396cc36c6e60704ab06c1fb1c4a46179c9120-put_pi_state
 * @id cpp/linux/c64396cc36c6e60704ab06c1fb1c4a46179c9120/put-pi-state
 * @description linux-c64396cc36c6e60704ab06c1fb1c4a46179c9120-put_pi_state 
 * @kind problem
 * @problem.severity error
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

predicate func_3(Parameter vpi_state_775) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="owner"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_state_775)
}

predicate func_4(Parameter vpi_state_775, Variable vowner_788) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=vowner_788
		and target_4.getRValue().(PointerFieldAccess).getTarget().getName()="owner"
		and target_4.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_state_775)
}

predicate func_5(Parameter vpi_state_775, Variable vowner_788) {
	exists(IfStmt target_5 |
		target_5.getCondition().(VariableAccess).getTarget()=vowner_788
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("list_del_init")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="list"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_state_775
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_raw_spin_unlock")
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_lock"
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vowner_788
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="owner"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_state_775)
}

predicate func_6(Variable vowner_788) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="pi_lock"
		and target_6.getQualifier().(VariableAccess).getTarget()=vowner_788)
}

predicate func_9(Parameter vpi_state_775, Variable vowner_788) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("rt_mutex_proxy_unlock")
		and target_9.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_9.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_state_775
		and target_9.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vowner_788
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="owner"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_state_775)
}

from Function func, Parameter vpi_state_775, Variable vowner_788
where
func_0(func)
and func_3(vpi_state_775)
and func_4(vpi_state_775, vowner_788)
and func_5(vpi_state_775, vowner_788)
and func_6(vowner_788)
and func_9(vpi_state_775, vowner_788)
and vpi_state_775.getType().hasName("futex_pi_state *")
and vowner_788.getType().hasName("task_struct *")
and vpi_state_775.getParentScope+() = func
and vowner_788.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
