/**
 * @name postgresql-0fcb8e2e0154dedea5c3c7da6dd2cffb731aac06-ExecOnConflictUpdate
 * @id cpp/postgresql/0fcb8e2e0154dedea5c3c7da6dd2cffb731aac06/ExecOnConflictUpdate
 * @description postgresql-0fcb8e2e0154dedea5c3c7da6dd2cffb731aac06-src/backend/executor/nodeModifyTable.c-ExecOnConflictUpdate CVE-2021-32028
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vresultRelInfo_1075, Parameter vmtstate_1074, ExprStmt target_1, ValueFieldAccess target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="mt_confljunk"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1074
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExecFilterJunk")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mt_confljunk"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1074
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pi_slot"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_onConflictSetProj"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1075
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vresultRelInfo_1075, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("ExecProject")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_onConflictSetProj"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1075
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_2(Parameter vmtstate_1074, ValueFieldAccess target_2) {
		target_2.getTarget().getName()="state"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="ps"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1074
}

predicate func_3(Parameter vmtstate_1074, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("TupleTableSlot **")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecUpdate")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="t_self"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("HeapTupleData")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="mt_conflproj"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1074
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="mt_epqstate"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1074
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(ValueFieldAccess).getTarget().getName()="state"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ps"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1074
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("bool")
}

from Function func, Parameter vresultRelInfo_1075, Parameter vmtstate_1074, ExprStmt target_1, ValueFieldAccess target_2, ExprStmt target_3
where
not func_0(vresultRelInfo_1075, vmtstate_1074, target_1, target_2, target_3, func)
and func_1(vresultRelInfo_1075, target_1)
and func_2(vmtstate_1074, target_2)
and func_3(vmtstate_1074, target_3)
and vresultRelInfo_1075.getType().hasName("ResultRelInfo *")
and vmtstate_1074.getType().hasName("ModifyTableState *")
and vresultRelInfo_1075.getFunction() = func
and vmtstate_1074.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
