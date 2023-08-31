/**
 * @name postgresql-cb2ae5741f2458a474ed3c31458d242e678ff229-ExecMergeMatched
 * @id cpp/postgresql/cb2ae5741f2458a474ed3c31458d242e678ff229/ExecMergeMatched
 * @description postgresql-cb2ae5741f2458a474ed3c31458d242e678ff229-src/backend/executor/nodeModifyTable.c-ExecMergeMatched CVE-2023-39418
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcommandType_2826, Parameter vresultRelInfo_2779, BlockStmt target_2, ConditionalExpr target_4, ExprStmt target_6) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="ri_WithCheckOptions"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_2779
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcommandType_2826
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vresultRelInfo_2779, BlockStmt target_2, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="ri_WithCheckOptions"
		and target_1.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_2779
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vcommandType_2826, Parameter vresultRelInfo_2779, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExecWithCheckOptions")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcommandType_2826
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vresultRelInfo_2779
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="ri_oldTupleSlot"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_2779
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="state"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ps"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mtstate"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ModifyTableContext *")
}

predicate func_4(Variable vcommandType_2826, ConditionalExpr target_4) {
		target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcommandType_2826
}

predicate func_6(Variable vcommandType_2826, Parameter vresultRelInfo_2779, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("ExecWithCheckOptions")
		and target_6.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcommandType_2826
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vresultRelInfo_2779
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="ri_oldTupleSlot"
		and target_6.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_2779
		and target_6.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="state"
		and target_6.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ps"
		and target_6.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mtstate"
		and target_6.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ModifyTableContext *")
}

from Function func, Variable vcommandType_2826, Parameter vresultRelInfo_2779, PointerFieldAccess target_1, BlockStmt target_2, ConditionalExpr target_4, ExprStmt target_6
where
not func_0(vcommandType_2826, vresultRelInfo_2779, target_2, target_4, target_6)
and func_1(vresultRelInfo_2779, target_2, target_1)
and func_2(vcommandType_2826, vresultRelInfo_2779, target_2)
and func_4(vcommandType_2826, target_4)
and func_6(vcommandType_2826, vresultRelInfo_2779, target_6)
and vcommandType_2826.getType().hasName("CmdType")
and vresultRelInfo_2779.getType().hasName("ResultRelInfo *")
and vcommandType_2826.(LocalVariable).getFunction() = func
and vresultRelInfo_2779.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
