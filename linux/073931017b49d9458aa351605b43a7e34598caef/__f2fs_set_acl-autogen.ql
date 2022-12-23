/**
 * @name linux-073931017b49d9458aa351605b43a7e34598caef-__f2fs_set_acl
 * @id cpp/linux/073931017b49d9458aa351605b43a7e34598caef/--f2fs-set-acl
 * @description linux-073931017b49d9458aa351605b43a7e34598caef-__f2fs_set_acl CVE-2016-7097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_201, Parameter vacl_202) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("posix_acl_equiv_mode")
		and not target_0.getTarget().hasName("posix_acl_update_mode")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vacl_202
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_201)
}

predicate func_2(Parameter vinode_201, Parameter vacl_202) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vacl_202
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("posix_acl_update_mode")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_201
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_201)
}

predicate func_5(Variable verror_207) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(VariableAccess).getTarget()=verror_207
		and target_5.getGreaterOperand().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=verror_207)
}

predicate func_6(Parameter vacl_202, Variable verror_207) {
	exists(IfStmt target_6 |
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verror_207
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vacl_202
		and target_6.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vacl_202)
}

from Function func, Parameter vinode_201, Parameter vacl_202, Variable verror_207
where
func_0(vinode_201, vacl_202)
and not func_2(vinode_201, vacl_202)
and func_5(verror_207)
and func_6(vacl_202, verror_207)
and vinode_201.getType().hasName("inode *")
and vacl_202.getType().hasName("posix_acl *")
and verror_207.getType().hasName("int")
and vinode_201.getParentScope+() = func
and vacl_202.getParentScope+() = func
and verror_207.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
