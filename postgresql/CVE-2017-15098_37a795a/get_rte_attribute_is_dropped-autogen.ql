/**
 * @name postgresql-37a795a60-get_rte_attribute_is_dropped
 * @id cpp/postgresql/37a795a60/get-rte-attribute-is-dropped
 * @description postgresql-37a795a60-src/backend/parser/parse_relation.c-get_rte_attribute_is_dropped CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrtfunc_2964, Variable vtupdesc_2971, LogicalAndExpr target_8, ExprStmt target_9) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getTarget()=vtupdesc_2971
		and target_0.getRValue().(FunctionCall).getTarget().hasName("get_expr_result_tupdesc")
		and target_0.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="funcexpr"
		and target_0.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrtfunc_2964
		and target_0.getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vrtfunc_2964, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="funcexpr"
		and target_2.getQualifier().(VariableAccess).getTarget()=vrtfunc_2964
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_3(Variable vtupdesc_2971, VariableAccess target_3) {
		target_3.getTarget()=vtupdesc_2971
		and target_3.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_4(LogicalAndExpr target_8, Function func, DeclStmt target_4) {
		target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_4.getEnclosingFunction() = func
}

predicate func_5(LogicalAndExpr target_8, Function func, DeclStmt target_5) {
		target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Variable vrtfunc_2964, Variable vfunctypclass_2969, Variable vfuncrettype_2970, Variable vtupdesc_2971, AssignExpr target_6) {
		target_6.getLValue().(VariableAccess).getTarget()=vfunctypclass_2969
		and target_6.getRValue().(FunctionCall).getTarget().hasName("get_expr_result_type")
		and target_6.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="funcexpr"
		and target_6.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrtfunc_2964
		and target_6.getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vfuncrettype_2970
		and target_6.getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtupdesc_2971
}

predicate func_7(Variable vfunctypclass_2969, BlockStmt target_11, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vfunctypclass_2969
		and target_7.getParent().(IfStmt).getThen()=target_11
}

predicate func_8(Variable vrtfunc_2964, LogicalAndExpr target_8) {
		target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("AttrNumber")
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("AttrNumber")
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="funccolcount"
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrtfunc_2964
}

predicate func_9(Variable vrtfunc_2964, ExprStmt target_9) {
		target_9.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_9.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="funccolcount"
		and target_9.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrtfunc_2964
}

predicate func_11(Variable vtupdesc_2971, BlockStmt target_11) {
		target_11.getStmt(1).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_11.getStmt(2).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_11.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Form_pg_attribute")
		and target_11.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="attrs"
		and target_11.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtupdesc_2971
		and target_11.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

from Function func, Variable vrtfunc_2964, Variable vfunctypclass_2969, Variable vfuncrettype_2970, Variable vtupdesc_2971, PointerFieldAccess target_2, VariableAccess target_3, DeclStmt target_4, DeclStmt target_5, AssignExpr target_6, EqualityOperation target_7, LogicalAndExpr target_8, ExprStmt target_9, BlockStmt target_11
where
not func_0(vrtfunc_2964, vtupdesc_2971, target_8, target_9)
and func_2(vrtfunc_2964, target_2)
and func_3(vtupdesc_2971, target_3)
and func_4(target_8, func, target_4)
and func_5(target_8, func, target_5)
and func_6(vrtfunc_2964, vfunctypclass_2969, vfuncrettype_2970, vtupdesc_2971, target_6)
and func_7(vfunctypclass_2969, target_11, target_7)
and func_8(vrtfunc_2964, target_8)
and func_9(vrtfunc_2964, target_9)
and func_11(vtupdesc_2971, target_11)
and vrtfunc_2964.getType().hasName("RangeTblFunction *")
and vfunctypclass_2969.getType().hasName("TypeFuncClass")
and vfuncrettype_2970.getType().hasName("Oid")
and vtupdesc_2971.getType().hasName("TupleDesc")
and vrtfunc_2964.(LocalVariable).getFunction() = func
and vfunctypclass_2969.(LocalVariable).getFunction() = func
and vfuncrettype_2970.(LocalVariable).getFunction() = func
and vtupdesc_2971.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
