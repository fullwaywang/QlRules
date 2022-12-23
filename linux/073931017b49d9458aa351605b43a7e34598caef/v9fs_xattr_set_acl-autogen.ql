/**
 * @name linux-073931017b49d9458aa351605b43a7e34598caef-v9fs_xattr_set_acl
 * @id cpp/linux/073931017b49d9458aa351605b43a7e34598caef/v9fs-xattr-set-acl
 * @description linux-073931017b49d9458aa351605b43a7e34598caef-v9fs_xattr_set_acl CVE-2016-7097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vacl_247, Variable vmode_279) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("posix_acl_equiv_mode")
		and not target_0.getTarget().hasName("posix_acl_update_mode")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vacl_247
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmode_279)
}

predicate func_1(Parameter vinode_242, Variable vacl_247) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vacl_247
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("posix_acl_update_mode")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_242
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand() instanceof ValueFieldAccess)
}

predicate func_2(Variable vacl_247) {
	exists(NotExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vacl_247
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt)
}

predicate func_3(Parameter vinode_242) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="i_mode"
		and target_3.getQualifier().(VariableAccess).getTarget()=vinode_242)
}

predicate func_4(Function func) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof Struct
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof RelationalOperation
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vvalue_243) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvalue_243
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_6(Parameter vsize_244) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_244
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_7(Variable viattr_284) {
	exists(ValueFieldAccess target_7 |
		target_7.getTarget().getName()="ia_mode"
		and target_7.getQualifier().(VariableAccess).getTarget()=viattr_284)
}

predicate func_8(Variable viattr_284) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ia_valid"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=viattr_284
		and target_8.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getValue()="1"
		and target_8.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_8.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof RelationalOperation)
}

predicate func_9(Parameter vdentry_242, Variable viattr_284) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("v9fs_vfs_setattr_dotl")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdentry_242
		and target_9.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=viattr_284
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof RelationalOperation)
}

predicate func_14(Variable vacl_247) {
	exists(DeclStmt target_14 |
		target_14.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof PointerFieldAccess
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vacl_247)
}

predicate func_15(Variable vmode_279) {
	exists(VariableAccess target_15 |
		target_15.getTarget()=vmode_279)
}

predicate func_19(Parameter vinode_242, Variable vretval_246, Variable vmode_279) {
	exists(ExprStmt target_19 |
		target_19.getExpr().(AssignExpr).getLValue() instanceof ValueFieldAccess
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vmode_279
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="2048"
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="1024"
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="512"
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="448"
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="56"
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="7"
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_242
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="2048"
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="1024"
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="512"
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="448"
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="56"
		and target_19.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="7"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vretval_246
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

from Function func, Parameter vdentry_242, Parameter vinode_242, Parameter vvalue_243, Parameter vsize_244, Variable vretval_246, Variable vacl_247, Variable vmode_279, Variable viattr_284
where
func_0(vacl_247, vmode_279)
and not func_1(vinode_242, vacl_247)
and not func_2(vacl_247)
and func_3(vinode_242)
and func_4(func)
and func_5(vvalue_243)
and func_6(vsize_244)
and func_7(viattr_284)
and func_8(viattr_284)
and func_9(vdentry_242, viattr_284)
and func_14(vacl_247)
and func_15(vmode_279)
and func_19(vinode_242, vretval_246, vmode_279)
and vdentry_242.getType().hasName("dentry *")
and vinode_242.getType().hasName("inode *")
and vvalue_243.getType().hasName("const void *")
and vsize_244.getType().hasName("size_t")
and vretval_246.getType().hasName("int")
and vacl_247.getType().hasName("posix_acl *")
and vmode_279.getType().hasName("umode_t")
and viattr_284.getType().hasName("iattr")
and vdentry_242.getParentScope+() = func
and vinode_242.getParentScope+() = func
and vvalue_243.getParentScope+() = func
and vsize_244.getParentScope+() = func
and vretval_246.getParentScope+() = func
and vacl_247.getParentScope+() = func
and vmode_279.getParentScope+() = func
and viattr_284.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
