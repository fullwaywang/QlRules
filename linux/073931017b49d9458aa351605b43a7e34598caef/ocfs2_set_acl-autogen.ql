/**
 * @name linux-073931017b49d9458aa351605b43a7e34598caef-ocfs2_set_acl
 * @id cpp/linux/073931017b49d9458aa351605b43a7e34598caef/ocfs2-set-acl
 * @description linux-073931017b49d9458aa351605b43a7e34598caef-ocfs2_set_acl CVE-2016-7097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vacl_228, Variable vmode_244) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("posix_acl_equiv_mode")
		and not target_0.getTarget().hasName("posix_acl_update_mode")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vacl_228
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmode_244)
}

predicate func_2(Parameter vinode_225, Parameter vacl_228, Variable vmode_244) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vacl_228
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("posix_acl_update_mode")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_225
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmode_244)
}

predicate func_4(Parameter vinode_225) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="i_mode"
		and target_4.getQualifier().(VariableAccess).getTarget()=vinode_225)
}

predicate func_5(Variable vret_235, Function func) {
	exists(ReturnStmt target_5 |
		target_5.getExpr().(VariableAccess).getTarget()=vret_235
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_9(Function func) {
	exists(Initializer target_9 |
		target_9.getExpr() instanceof PointerFieldAccess
		and target_9.getExpr().getEnclosingFunction() = func)
}

predicate func_10(Variable vret_235) {
	exists(RelationalOperation target_10 |
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getLesserOperand().(VariableAccess).getTarget()=vret_235
		and target_10.getGreaterOperand().(Literal).getValue()="0"
		and target_10.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vret_235)
}

predicate func_11(Parameter vacl_228, Variable vret_235) {
	exists(IfStmt target_11 |
		target_11.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_235
		and target_11.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vacl_228
		and target_11.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vacl_228)
}

from Function func, Parameter vinode_225, Parameter vacl_228, Variable vret_235, Variable vmode_244
where
func_0(vacl_228, vmode_244)
and not func_2(vinode_225, vacl_228, vmode_244)
and func_4(vinode_225)
and func_5(vret_235, func)
and func_9(func)
and func_10(vret_235)
and func_11(vacl_228, vret_235)
and vinode_225.getType().hasName("inode *")
and vacl_228.getType().hasName("posix_acl *")
and vret_235.getType().hasName("int")
and vmode_244.getType().hasName("umode_t")
and vinode_225.getParentScope+() = func
and vacl_228.getParentScope+() = func
and vret_235.getParentScope+() = func
and vmode_244.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
