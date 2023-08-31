/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-ExecComputeStoredGenerated
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/ExecComputeStoredGenerated
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/executor/nodeModifyTable.c-ExecComputeStoredGenerated CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vresultRelInfo_253, Parameter vestate_254, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("ExecGetExtraUpdatedCols")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vresultRelInfo_253
		and target_0.getArgument(1).(VariableAccess).getTarget()=vestate_254
		and target_0.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("bms_is_member")
		and target_0.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_0.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(SubExpr).getRightOperand().(UnaryMinusExpr).getValue()="-7"
		and target_0.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="extraUpdatedCols"
		and target_0.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier() instanceof FunctionCall
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(VariableAccess).getLocation())
		and target_0.getArgument(1).(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vestate_254, VariableAccess target_1) {
		target_1.getTarget()=vestate_254
		and target_1.getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_2(Parameter vresultRelInfo_253, VariableAccess target_2) {
		target_2.getTarget()=vresultRelInfo_253
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(PointerFieldAccess).getQualifier() instanceof FunctionCall
}

predicate func_3(Parameter vresultRelInfo_253, Parameter vestate_254, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="extraUpdatedCols"
		and target_3.getQualifier().(FunctionCall).getTarget().hasName("exec_rt_fetch")
		and target_3.getQualifier().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RangeTableIndex"
		and target_3.getQualifier().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_253
		and target_3.getQualifier().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vestate_254
}

predicate func_4(Parameter vresultRelInfo_253, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ri_NumGeneratedNeeded"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_253
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_5(Parameter vresultRelInfo_253, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ri_GeneratedExprs"
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_253
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_6(Parameter vestate_254, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("MemoryContext")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("MemoryContextSwitchTo")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="es_query_cxt"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vestate_254
}

predicate func_7(Parameter vresultRelInfo_253, Parameter vestate_254, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ri_GeneratedExprs"
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_253
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecPrepareExpr")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Expr *")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vestate_254
}

from Function func, Parameter vresultRelInfo_253, Parameter vestate_254, VariableAccess target_1, VariableAccess target_2, PointerFieldAccess target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7
where
not func_0(vresultRelInfo_253, vestate_254, target_4, target_5, target_6, target_7)
and func_1(vestate_254, target_1)
and func_2(vresultRelInfo_253, target_2)
and func_3(vresultRelInfo_253, vestate_254, target_3)
and func_4(vresultRelInfo_253, target_4)
and func_5(vresultRelInfo_253, target_5)
and func_6(vestate_254, target_6)
and func_7(vresultRelInfo_253, vestate_254, target_7)
and vresultRelInfo_253.getType().hasName("ResultRelInfo *")
and vestate_254.getType().hasName("EState *")
and vresultRelInfo_253.getFunction() = func
and vestate_254.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
