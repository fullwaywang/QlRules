/**
 * @name postgresql-d479d00285255d422a2b38f1cfaa35808968a08c-tts_heap_getsysattr
 * @id cpp/postgresql/d479d00285255d422a2b38f1cfaa35808968a08c/tts-heap-getsysattr
 * @description postgresql-d479d00285255d422a2b38f1cfaa35808968a08c-src/backend/executor/execTuples.c-tts_heap_getsysattr CVE-2021-32029
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vhslot_334, FunctionCall target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tuple"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhslot_334
		and target_0.getThen().(DoStmt).getCondition() instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getValue()="1"
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("errstart_cold")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("errstart")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vhslot_334, FunctionCall target_1) {
		target_1.getTarget().hasName("heap_getsysattr")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="tuple"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhslot_334
		and target_1.getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getArgument(2).(PointerFieldAccess).getTarget().getName()="tts_tupleDescriptor"
		and target_1.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_1.getArgument(3).(VariableAccess).getTarget().getType().hasName("bool *")
}

from Function func, Variable vhslot_334, FunctionCall target_1
where
not func_0(vhslot_334, target_1, func)
and func_1(vhslot_334, target_1)
and vhslot_334.getType().hasName("HeapTupleTableSlot *")
and vhslot_334.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
