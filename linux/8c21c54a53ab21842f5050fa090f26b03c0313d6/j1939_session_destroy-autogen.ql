/**
 * @name linux-8c21c54a53ab21842f5050fa090f26b03c0313d6-j1939_session_destroy
 * @id cpp/linux/8c21c54a53ab21842f5050fa090f26b03c0313d6/j1939-session-destroy
 * @description linux-8c21c54a53ab21842f5050fa090f26b03c0313d6-j1939_session_destroy 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("skb_queue_purge")
		and not target_0.getTarget().hasName("kfree_skb")
		and target_0.getArgument(0) instanceof AddressOfExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getStmt(0)=target_1)
}

predicate func_2(Function func) {
	exists(WhileStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("sk_buff *")
		and target_2.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("skb_dequeue")
		and target_2.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("skb_unref")
		and target_2.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("sk_buff *")
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree_skb")
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("sk_buff *")
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_2))
}

predicate func_6(Parameter vsession_261) {
	exists(AddressOfExpr target_6 |
		target_6.getOperand().(PointerFieldAccess).getTarget().getName()="skb_queue"
		and target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_261
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

from Function func, Parameter vsession_261
where
func_0(func)
and not func_1(func)
and not func_2(func)
and func_6(vsession_261)
and vsession_261.getType().hasName("j1939_session *")
and vsession_261.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
