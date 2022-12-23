/**
 * @name linux-6d8c50dcb029872b298eea68cc6209c866fd3e14-sockfs_setattr
 * @id cpp/linux/6d8c50dcb029872b298eea68cc6209c866fd3e14/sockfs_setattr
 * @description linux-6d8c50dcb029872b298eea68cc6209c866fd3e14-sockfs_setattr 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter viattr_537, Variable verr_539, Variable vsock_542) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="sk"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_542
		and target_0.getThen() instanceof ExprStmt
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_539
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-2"
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="2"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=verr_539
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ia_valid"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viattr_537
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1")
}

predicate func_1(Parameter viattr_537, Variable verr_539, Variable vsock_542) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sk_uid"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sk"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_542
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="ia_uid"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viattr_537
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=verr_539
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ia_valid"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viattr_537
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1")
}

predicate func_2(Variable verr_539, Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(VariableAccess).getTarget()=verr_539
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

from Function func, Parameter viattr_537, Variable verr_539, Variable vsock_542
where
not func_0(viattr_537, verr_539, vsock_542)
and func_1(viattr_537, verr_539, vsock_542)
and viattr_537.getType().hasName("iattr *")
and verr_539.getType().hasName("int")
and func_2(verr_539, func)
and vsock_542.getType().hasName("socket *")
and viattr_537.getParentScope+() = func
and verr_539.getParentScope+() = func
and vsock_542.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
