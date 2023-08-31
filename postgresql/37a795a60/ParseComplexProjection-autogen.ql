/**
 * @name postgresql-37a795a60-ParseComplexProjection
 * @id cpp/postgresql/37a795a60/ParseComplexProjection
 * @description postgresql-37a795a60-src/backend/parser/parse_func.c-ParseComplexProjection CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfirst_arg_1793, Variable vtupdesc_1796, ExprStmt target_6, ExprStmt target_7, RelationalOperation target_8) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getTarget()=vtupdesc_1796
		and target_0.getRValue().(FunctionCall).getTarget().hasName("get_expr_result_tupdesc")
		and target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfirst_arg_1793
		and target_0.getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_0.getLValue().(VariableAccess).getLocation().isBefore(target_8.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtupdesc_1796, ReturnStmt target_9, ExprStmt target_6, AddressOfExpr target_10) {
	exists(NotExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vtupdesc_1796
		and target_1.getParent().(IfStmt).getThen()=target_9
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getOperand().(VariableAccess).getLocation())
		and target_1.getOperand().(VariableAccess).getLocation().isBefore(target_10.getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vfirst_arg_1793, VariableAccess target_2) {
		target_2.getTarget()=vfirst_arg_1793
		and target_2.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand() instanceof FunctionCall
}

predicate func_3(Variable vtupdesc_1796, VariableAccess target_3) {
		target_3.getTarget()=vtupdesc_1796
		and target_3.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(NEExpr).getAnOperand() instanceof FunctionCall
}

predicate func_5(Parameter vfirst_arg_1793, Variable vtupdesc_1796, ReturnStmt target_9, EqualityOperation target_5) {
		target_5.getAnOperand().(FunctionCall).getTarget().hasName("get_expr_result_type")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfirst_arg_1793
		and target_5.getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_5.getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtupdesc_1796
		and target_5.getParent().(IfStmt).getThen()=target_9
}

predicate func_6(Parameter vfirst_arg_1793, Variable vtupdesc_1796, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtupdesc_1796
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("expandRecordVariable")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ParseState *")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfirst_arg_1793
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_7(Parameter vfirst_arg_1793, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="arg"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("FieldSelect *")
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vfirst_arg_1793
}

predicate func_8(Variable vtupdesc_1796, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="natts"
		and target_8.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtupdesc_1796
}

predicate func_9(ReturnStmt target_9) {
		target_9.getExpr().(Literal).getValue()="0"
}

predicate func_10(Variable vtupdesc_1796, AddressOfExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vtupdesc_1796
}

from Function func, Parameter vfirst_arg_1793, Variable vtupdesc_1796, VariableAccess target_2, VariableAccess target_3, EqualityOperation target_5, ExprStmt target_6, ExprStmt target_7, RelationalOperation target_8, ReturnStmt target_9, AddressOfExpr target_10
where
not func_0(vfirst_arg_1793, vtupdesc_1796, target_6, target_7, target_8)
and not func_1(vtupdesc_1796, target_9, target_6, target_10)
and func_2(vfirst_arg_1793, target_2)
and func_3(vtupdesc_1796, target_3)
and func_5(vfirst_arg_1793, vtupdesc_1796, target_9, target_5)
and func_6(vfirst_arg_1793, vtupdesc_1796, target_6)
and func_7(vfirst_arg_1793, target_7)
and func_8(vtupdesc_1796, target_8)
and func_9(target_9)
and func_10(vtupdesc_1796, target_10)
and vfirst_arg_1793.getType().hasName("Node *")
and vtupdesc_1796.getType().hasName("TupleDesc")
and vfirst_arg_1793.getFunction() = func
and vtupdesc_1796.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
