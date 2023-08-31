/**
 * @name postgresql-935e77d527a018b652f247c7374c558871210db6-calc_rangesel
 * @id cpp/postgresql/935e77d527a018b652f247c7374c558871210db6/calc-rangesel
 * @description postgresql-935e77d527a018b652f247c7374c558871210db6-src/backend/utils/adt/rangetypes_selfuncs.c-calc_rangesel CVE-2017-7484
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vvardata_227, BlockStmt target_6) {
	exists(UnaryMinusExpr target_1 |
		target_1.getValue()="-1"
		and target_1.getParent().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_1.getParent().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_227
		and target_1.getParent().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_1.getParent().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_227
		and target_1.getParent().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_1.getParent().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_227
		and target_1.getParent().(FunctionCall).getArgument(3).(Literal).getValue()="6"
		and target_1.getParent().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getArgument(6).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getArgument(7).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getArgument(8).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("float4 *")
		and target_1.getParent().(FunctionCall).getArgument(9).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_6)
}

predicate func_3(Parameter vvardata_227, FunctionCall target_7, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="atttype"
		and target_3.getQualifier().(VariableAccess).getTarget()=vvardata_227
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getQualifier().(VariableAccess).getLocation())
}

predicate func_4(Parameter vvardata_227, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="atttypmod"
		and target_4.getQualifier().(VariableAccess).getTarget()=vvardata_227
}

predicate func_5(Parameter vvardata_227, FunctionCall target_7, ExprStmt target_8, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="atttype"
		and target_5.getQualifier().(VariableAccess).getTarget()=vvardata_227
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getQualifier().(VariableAccess).getLocation())
		and target_5.getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_6(BlockStmt target_6) {
		target_6.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_6.getStmt(0).(IfStmt).getThen().(DoStmt).getCondition() instanceof Literal
		and target_6.getStmt(0).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("elog_start")
		and target_6.getStmt(0).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_6.getStmt(0).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_6.getStmt(0).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_6.getStmt(0).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("elog_finish")
		and target_6.getStmt(0).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_6.getStmt(0).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="invalid empty fraction statistic"
}

predicate func_7(Parameter vvardata_227, FunctionCall target_7) {
		target_7.getTarget().hasName("get_attstatsslot")
		and target_7.getArgument(0).(PointerFieldAccess).getTarget().getName()="statsTuple"
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_227
		and target_7.getArgument(1).(PointerFieldAccess).getTarget().getName()="atttype"
		and target_7.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_227
		and target_7.getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_7.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvardata_227
		and target_7.getArgument(3).(Literal).getValue()="6"
		and target_7.getArgument(4).(Literal).getValue()="0"
		and target_7.getArgument(5).(Literal).getValue()="0"
		and target_7.getArgument(6).(Literal).getValue()="0"
		and target_7.getArgument(7).(Literal).getValue()="0"
		and target_7.getArgument(8).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("float4 *")
		and target_7.getArgument(9).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_8(Parameter vvardata_227, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("double")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calc_hist_selectivity")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("TypeCacheEntry *")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvardata_227
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("RangeType *")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("Oid")
}

from Function func, Parameter vvardata_227, PointerFieldAccess target_3, PointerFieldAccess target_4, PointerFieldAccess target_5, BlockStmt target_6, FunctionCall target_7, ExprStmt target_8
where
not func_1(vvardata_227, target_6)
and func_3(vvardata_227, target_7, target_3)
and func_4(vvardata_227, target_4)
and func_5(vvardata_227, target_7, target_8, target_5)
and func_6(target_6)
and func_7(vvardata_227, target_7)
and func_8(vvardata_227, target_8)
and vvardata_227.getType().hasName("VariableStatData *")
and vvardata_227.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
