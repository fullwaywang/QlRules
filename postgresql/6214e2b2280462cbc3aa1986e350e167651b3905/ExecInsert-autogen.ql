/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-ExecInsert
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/ExecInsert
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/executor/nodeModifyTable.c-ExecInsert CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vresultRelInfo_386, ExprStmt target_3, LogicalAndExpr target_4) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="ri_RootResultRelInfo"
		and target_0.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_386
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation())
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vresultRelInfo_386, VariableAccess target_1) {
		target_1.getTarget()=vresultRelInfo_386
}

predicate func_2(Parameter vresultRelInfo_386, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="ri_PartitionRoot"
		and target_2.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_386
}

predicate func_3(Parameter vresultRelInfo_386, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("ExecConstraints")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_386
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("TupleTableSlot *")
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("EState *")
}

predicate func_4(Parameter vresultRelInfo_386, LogicalAndExpr target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="relispartition"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Relation")
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ri_PartitionRoot"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_386
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="ri_TrigDesc"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_386
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="trig_insert_before_row"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_TrigDesc"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_386
}

from Function func, Parameter vresultRelInfo_386, VariableAccess target_1, PointerFieldAccess target_2, ExprStmt target_3, LogicalAndExpr target_4
where
not func_0(vresultRelInfo_386, target_3, target_4)
and func_1(vresultRelInfo_386, target_1)
and func_2(vresultRelInfo_386, target_2)
and func_3(vresultRelInfo_386, target_3)
and func_4(vresultRelInfo_386, target_4)
and vresultRelInfo_386.getType().hasName("ResultRelInfo *")
and vresultRelInfo_386.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
