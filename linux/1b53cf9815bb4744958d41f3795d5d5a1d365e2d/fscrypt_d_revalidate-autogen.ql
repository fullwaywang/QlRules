/**
 * @name linux-1b53cf9815bb4744958d41f3795d5d5a1d365e2d-fscrypt_d_revalidate
 * @id cpp/linux/1b53cf9815bb4744958d41f3795d5d5a1d365e2d/fscrypt-d-revalidate
 * @description linux-1b53cf9815bb4744958d41f3795d5d5a1d365e2d-fscrypt_d_revalidate 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdir_329, Variable vci_330) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="i_crypt_info"
		and target_0.getQualifier().(FunctionCall).getTarget().hasName("d_inode")
		and target_0.getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdir_329
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vci_330)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vci_330) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vci_330
		and target_2.getRValue() instanceof PointerFieldAccess)
}

predicate func_3(Variable vci_330, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vci_330
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="ci_keyring_key"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_330
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ci_keyring_key"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vci_330
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="134"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="7"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vci_330
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Variable vci_330, Variable vdir_has_key_331, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdir_has_key_331
		and target_4.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vci_330
		and target_4.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

from Function func, Variable vdir_329, Variable vci_330, Variable vdir_has_key_331
where
func_0(vdir_329, vci_330)
and func_1(func)
and func_2(vci_330)
and func_3(vci_330, func)
and func_4(vci_330, vdir_has_key_331, func)
and vdir_329.getType().hasName("dentry *")
and vci_330.getType().hasName("fscrypt_info *")
and vdir_has_key_331.getType().hasName("int")
and vdir_329.getParentScope+() = func
and vci_330.getParentScope+() = func
and vdir_has_key_331.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
