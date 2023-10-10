/**
 * @name linux-073931017b49d9458aa351605b43a7e34598caef-orangefs_set_acl
 * @id cpp/linux/073931017b49d9458aa351605b43a7e34598caef/orangefs-set-acl
 * @description linux-073931017b49d9458aa351605b43a7e34598caef-orangefs_set_acl CVE-2016-7097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="%s: posix_acl_equiv_mode err: %d\n"
		and not target_0.getValue()="%s: posix_acl_update_mode err: %d\n"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vacl_64, Variable vmode_76) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("posix_acl_equiv_mode")
		and not target_1.getTarget().hasName("posix_acl_update_mode")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vacl_64
		and target_1.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmode_76)
}

predicate func_3(Parameter vacl_64, Variable vmode_76, Parameter vinode_64) {
	exists(AddressOfExpr target_3 |
		target_3.getOperand().(VariableAccess).getTarget()=vacl_64
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("posix_acl_update_mode")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_64
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmode_76)
}

predicate func_4(Parameter vinode_64) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="i_mode"
		and target_4.getQualifier().(VariableAccess).getTarget()=vinode_64)
}

predicate func_5(Variable verror_67, Variable v__func__) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(VariableAccess).getTarget()=verror_67
		and target_5.getGreaterOperand().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__pr_err")
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=v__func__
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=verror_67
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getTarget()=verror_67)
}

predicate func_8(Function func) {
	exists(Initializer target_8 |
		target_8.getExpr() instanceof PointerFieldAccess
		and target_8.getExpr().getEnclosingFunction() = func)
}

predicate func_9(Parameter vacl_64, Variable verror_67) {
	exists(IfStmt target_9 |
		target_9.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verror_67
		and target_9.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vacl_64
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vacl_64)
}

from Function func, Parameter vacl_64, Variable verror_67, Variable vmode_76, Variable v__func__, Parameter vinode_64
where
func_0(func)
and func_1(vacl_64, vmode_76)
and not func_3(vacl_64, vmode_76, vinode_64)
and func_4(vinode_64)
and func_5(verror_67, v__func__)
and func_8(func)
and func_9(vacl_64, verror_67)
and vacl_64.getType().hasName("posix_acl *")
and verror_67.getType().hasName("int")
and vmode_76.getType().hasName("umode_t")
and v__func__.getType().hasName("const char[17]")
and vinode_64.getType().hasName("inode *")
and vacl_64.getParentScope+() = func
and verror_67.getParentScope+() = func
and vmode_76.getParentScope+() = func
and not v__func__.getParentScope+() = func
and vinode_64.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
