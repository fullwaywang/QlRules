/**
 * @name linux-073931017b49d9458aa351605b43a7e34598caef-jffs2_set_acl
 * @id cpp/linux/073931017b49d9458aa351605b43a7e34598caef/jffs2-set-acl
 * @description linux-073931017b49d9458aa351605b43a7e34598caef-jffs2_set_acl CVE-2016-7097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vacl_228, Variable vmode_236) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("posix_acl_equiv_mode")
		and not target_0.getTarget().hasName("posix_acl_update_mode")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vacl_228
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmode_236)
}

predicate func_2(Parameter vinode_228, Parameter vacl_228, Variable vmode_236) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vacl_228
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("posix_acl_update_mode")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_228
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmode_236)
}

predicate func_4(Parameter vinode_228) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="i_mode"
		and target_4.getQualifier().(VariableAccess).getTarget()=vinode_228)
}

predicate func_5(Parameter vacl_228, Variable vrc_230) {
	exists(IfStmt target_5 |
		target_5.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrc_230
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_5.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vrc_230
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vacl_228)
}

predicate func_6(Variable vrc_230, Function func) {
	exists(ReturnStmt target_6 |
		target_6.getExpr().(VariableAccess).getTarget()=vrc_230
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_9(Function func) {
	exists(Initializer target_9 |
		target_9.getExpr() instanceof PointerFieldAccess
		and target_9.getExpr().getEnclosingFunction() = func)
}

predicate func_13(Parameter vinode_228, Parameter vacl_228, Parameter vtype_228, Variable vrc_230) {
	exists(NotExpr target_13 |
		target_13.getOperand().(VariableAccess).getTarget()=vrc_230
		and target_13.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("set_cached_acl")
		and target_13.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_228
		and target_13.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtype_228
		and target_13.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vacl_228)
}

from Function func, Parameter vinode_228, Parameter vacl_228, Parameter vtype_228, Variable vrc_230, Variable vmode_236
where
func_0(vacl_228, vmode_236)
and not func_2(vinode_228, vacl_228, vmode_236)
and func_4(vinode_228)
and func_5(vacl_228, vrc_230)
and func_6(vrc_230, func)
and func_9(func)
and vinode_228.getType().hasName("inode *")
and vacl_228.getType().hasName("posix_acl *")
and vrc_230.getType().hasName("int")
and func_13(vinode_228, vacl_228, vtype_228, vrc_230)
and vmode_236.getType().hasName("umode_t")
and vinode_228.getParentScope+() = func
and vacl_228.getParentScope+() = func
and vtype_228.getParentScope+() = func
and vrc_230.getParentScope+() = func
and vmode_236.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
