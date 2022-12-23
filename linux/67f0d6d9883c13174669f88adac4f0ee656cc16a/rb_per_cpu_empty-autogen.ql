/**
 * @name linux-67f0d6d9883c13174669f88adac4f0ee656cc16a-rb_per_cpu_empty
 * @id cpp/linux/67f0d6d9883c13174669f88adac4f0ee656cc16a/rb_per_cpu_empty
 * @description linux-67f0d6d9883c13174669f88adac4f0ee656cc16a-rb_per_cpu_empty 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand() instanceof PointerFieldAccess
		and target_0.getCondition().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition() instanceof EqualityOperation
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1))
}

predicate func_2(Variable vhead_3876, Variable vcommit_3877, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcommit_3877
		and target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhead_3876
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_2))
}

predicate func_4(Variable vreader_3875) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="read"
		and target_4.getQualifier().(VariableAccess).getTarget()=vreader_3875)
}

predicate func_5(Variable vreader_3875) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("rb_page_commit")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vreader_3875)
}

predicate func_6(Variable vcommit_3877, Variable vreader_3875) {
	exists(EqualityOperation target_6 |
		target_6.getAnOperand().(VariableAccess).getTarget()=vcommit_3877
		and target_6.getAnOperand().(VariableAccess).getTarget()=vreader_3875)
}

predicate func_7(Variable vcommit_3877) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("rb_page_commit")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vcommit_3877)
}

predicate func_10(Variable vhead_3876, Variable vcommit_3877) {
	exists(LogicalAndExpr target_10 |
		target_10.getAnOperand().(EqualityOperation).getAnOperand() instanceof PointerFieldAccess
		and target_10.getAnOperand().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcommit_3877
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vhead_3876
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="read"
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhead_3876
		and target_10.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof FunctionCall)
}

from Function func, Variable vhead_3876, Variable vcommit_3877, Variable vreader_3875
where
not func_0(func)
and not func_1(func)
and not func_2(vhead_3876, vcommit_3877, func)
and func_4(vreader_3875)
and func_5(vreader_3875)
and func_6(vcommit_3877, vreader_3875)
and func_7(vcommit_3877)
and func_10(vhead_3876, vcommit_3877)
and vhead_3876.getType().hasName("buffer_page *")
and vcommit_3877.getType().hasName("buffer_page *")
and vreader_3875.getType().hasName("buffer_page *")
and vhead_3876.getParentScope+() = func
and vcommit_3877.getParentScope+() = func
and vreader_3875.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
