/**
 * @name linux-7a7b5df84b6b4e5d599c7289526eed96541a0654-cp2112_probe
 * @id cpp/linux/7a7b5df84b6b4e5d599c7289526eed96541a0654/cp2112-probe
 * @description linux-7a7b5df84b6b4e5d599c7289526eed96541a0654-cp2112_probe 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdev_1224) {
	exists(SizeofExprOperator target_0 |
		target_0.getValue()="3088"
		and target_0.getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdev_1224)
}

predicate func_1(Variable v__key_1238) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("__raw_spin_lock_init")
		and not target_1.getTarget().hasName("__mutex_init")
		and target_1.getArgument(0).(AddressOfExpr).getOperand() instanceof ValueFieldAccess
		and target_1.getArgument(1).(StringLiteral).getValue()="&(&dev->lock)->rlock"
		and target_1.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=v__key_1238)
}

predicate func_2(Variable v__key_1238, Variable vdev_1224) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1224
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__mutex_init")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="&dev->lock"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=v__key_1238)
}

predicate func_4(Function func) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof Struct
		and target_4.getEnclosingFunction() = func)
}

predicate func_6(Variable vdev_1224) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("spinlock_check")
		and target_6.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_6.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1224)
}

predicate func_7(Function func) {
	exists(DoStmt target_7 |
		target_7.getCondition().(Literal).getValue()="0"
		and target_7.getStmt().(BlockStmt).getStmt(0) instanceof DeclStmt
		and target_7.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr() instanceof FunctionCall
		and target_7.getEnclosingFunction() = func)
}

predicate func_9(Variable vdev_1224) {
	exists(ValueFieldAccess target_9 |
		target_9.getTarget().getName()="rlock"
		and target_9.getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1224)
}

from Function func, Variable v__key_1238, Variable vdev_1224
where
func_0(vdev_1224)
and func_1(v__key_1238)
and not func_2(v__key_1238, vdev_1224)
and func_4(func)
and func_6(vdev_1224)
and func_7(func)
and func_9(vdev_1224)
and v__key_1238.getType().hasName("lock_class_key")
and vdev_1224.getType().hasName("cp2112_device *")
and v__key_1238.getParentScope+() = func
and vdev_1224.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
