/**
 * @name postgresql-37a795a60-get_name_for_var_field
 * @id cpp/postgresql/37a795a60/get-name-for-var-field
 * @description postgresql-37a795a60-src/backend/utils/adt/ruleutils.c-get_name_for_var_field CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtupleDesc_6694, Parameter vvar_6687, FunctionCall target_0) {
		target_0.getTarget().hasName("lookup_rowtype_tupdesc_copy")
		and not target_0.getTarget().hasName("get_expr_result_tupdesc")
		and target_0.getArgument(0).(FunctionCall).getTarget().hasName("exprType")
		and target_0.getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_6687
		and target_0.getArgument(1).(FunctionCall).getTarget().hasName("exprTypmod")
		and target_0.getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_6687
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtupleDesc_6694
}

predicate func_1(Variable vtupleDesc_6694, Variable vexpr_6695, FunctionCall target_1) {
		target_1.getTarget().hasName("lookup_rowtype_tupdesc_copy")
		and not target_1.getTarget().hasName("get_expr_result_tupdesc")
		and target_1.getArgument(0).(FunctionCall).getTarget().hasName("exprType")
		and target_1.getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpr_6695
		and target_1.getArgument(1).(FunctionCall).getTarget().hasName("exprTypmod")
		and target_1.getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpr_6695
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtupleDesc_6694
}

predicate func_2(LogicalOrExpr target_15, Function func, ExprStmt target_2) {
		target_2.getExpr().(Literal).getValue()="1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Parameter vvar_6687, VariableAccess target_3) {
		target_3.getTarget()=vvar_6687
		and target_3.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand() instanceof FunctionCall
}

predicate func_5(Variable vexpr_6695, VariableAccess target_5) {
		target_5.getTarget()=vexpr_6695
		and target_5.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand() instanceof FunctionCall
}

predicate func_7(Variable vtupleDesc_6694, Parameter vvar_6687, LogicalOrExpr target_15, IfStmt target_7) {
		target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_expr_result_type")
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_6687
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtupleDesc_6694
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtupleDesc_6694
		and target_7.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

predicate func_8(Parameter vvar_6687, FunctionCall target_17, VariableAccess target_8) {
		target_8.getTarget()=vvar_6687
		and target_8.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("exprType")
		and target_8.getLocation().isBefore(target_17.getArgument(0).(VariableAccess).getLocation())
}

predicate func_9(Parameter vvar_6687, FunctionCall target_18, ExprStmt target_19, VariableAccess target_9) {
		target_9.getTarget()=vvar_6687
		and target_9.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("exprTypmod")
		and target_18.getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getLocation())
		and target_9.getLocation().isBefore(target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_10(Variable vtupleDesc_6694, Variable vexpr_6695, Function func, IfStmt target_10) {
		target_10.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_expr_result_type")
		and target_10.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexpr_6695
		and target_10.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_10.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtupleDesc_6694
		and target_10.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtupleDesc_6694
		and target_10.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

predicate func_11(Variable vexpr_6695, FunctionCall target_21, VariableAccess target_11) {
		target_11.getTarget()=vexpr_6695
		and target_11.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("exprType")
		and target_11.getLocation().isBefore(target_21.getArgument(0).(VariableAccess).getLocation())
}

predicate func_12(Variable vexpr_6695, FunctionCall target_22, VariableAccess target_12) {
		target_12.getTarget()=vexpr_6695
		and target_12.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("exprTypmod")
		and target_22.getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getLocation())
}

predicate func_14(Function func, ExprStmt target_14) {
		target_14.getExpr().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Parameter vvar_6687, LogicalOrExpr target_15) {
		target_15.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_15.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvar_6687
		and target_15.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="vartype"
		and target_15.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvar_6687
		and target_15.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2249"
}

predicate func_17(Parameter vvar_6687, FunctionCall target_17) {
		target_17.getTarget().hasName("exprTypmod")
		and target_17.getArgument(0).(VariableAccess).getTarget()=vvar_6687
}

predicate func_18(Parameter vvar_6687, FunctionCall target_18) {
		target_18.getTarget().hasName("exprType")
		and target_18.getArgument(0).(VariableAccess).getTarget()=vvar_6687
}

predicate func_19(Parameter vvar_6687, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="varlevelsup"
		and target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvar_6687
		and target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_21(Variable vexpr_6695, FunctionCall target_21) {
		target_21.getTarget().hasName("exprTypmod")
		and target_21.getArgument(0).(VariableAccess).getTarget()=vexpr_6695
}

predicate func_22(Variable vexpr_6695, FunctionCall target_22) {
		target_22.getTarget().hasName("exprType")
		and target_22.getArgument(0).(VariableAccess).getTarget()=vexpr_6695
}

from Function func, Variable vtupleDesc_6694, Variable vexpr_6695, Parameter vvar_6687, FunctionCall target_0, FunctionCall target_1, ExprStmt target_2, VariableAccess target_3, VariableAccess target_5, IfStmt target_7, VariableAccess target_8, VariableAccess target_9, IfStmt target_10, VariableAccess target_11, VariableAccess target_12, ExprStmt target_14, LogicalOrExpr target_15, FunctionCall target_17, FunctionCall target_18, ExprStmt target_19, FunctionCall target_21, FunctionCall target_22
where
func_0(vtupleDesc_6694, vvar_6687, target_0)
and func_1(vtupleDesc_6694, vexpr_6695, target_1)
and func_2(target_15, func, target_2)
and func_3(vvar_6687, target_3)
and func_5(vexpr_6695, target_5)
and func_7(vtupleDesc_6694, vvar_6687, target_15, target_7)
and func_8(vvar_6687, target_17, target_8)
and func_9(vvar_6687, target_18, target_19, target_9)
and func_10(vtupleDesc_6694, vexpr_6695, func, target_10)
and func_11(vexpr_6695, target_21, target_11)
and func_12(vexpr_6695, target_22, target_12)
and func_14(func, target_14)
and func_15(vvar_6687, target_15)
and func_17(vvar_6687, target_17)
and func_18(vvar_6687, target_18)
and func_19(vvar_6687, target_19)
and func_21(vexpr_6695, target_21)
and func_22(vexpr_6695, target_22)
and vtupleDesc_6694.getType().hasName("TupleDesc")
and vexpr_6695.getType().hasName("Node *")
and vvar_6687.getType().hasName("Var *")
and vtupleDesc_6694.(LocalVariable).getFunction() = func
and vexpr_6695.(LocalVariable).getFunction() = func
and vvar_6687.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
