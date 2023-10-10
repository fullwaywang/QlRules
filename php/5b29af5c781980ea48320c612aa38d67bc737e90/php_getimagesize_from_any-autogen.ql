/**
 * @name php-5b29af5c781980ea48320c612aa38d67bc737e90-php_getimagesize_from_any
 * @id cpp/php/5b29af5c781980ea48320c612aa38d67bc737e90/php-getimagesize-from-any
 * @description php-5b29af5c781980ea48320c612aa38d67bc737e90-ext/standard/image.c-php_getimagesize_from_any CVE-2020-7068
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmode_1486, Variable vinput_1489, Variable vinput_len_1490, EqualityOperation target_3, AddressOfExpr target_4, ExprStmt target_5, AddressOfExpr target_6, ExprStmt target_7, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vmode_1486
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinput_1489
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vinput_len_1490
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("php_error_docref0")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="2"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid path"
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_2(Function func, ReturnStmt target_2) {
		target_2.toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter vmode_1486, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vmode_1486
		and target_3.getAnOperand().(Literal).getValue()="1"
}

predicate func_4(Variable vinput_1489, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vinput_1489
}

predicate func_5(Variable vinput_1489, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_php_stream_open_wrapper_ex")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinput_1489
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="rb"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getValue()="24"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_6(Variable vinput_len_1490, AddressOfExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vinput_len_1490
}

predicate func_7(Variable vinput_1489, Variable vinput_len_1490, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_php_stream_memory_open")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="1"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinput_1489
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vinput_len_1490
}

from Function func, Parameter vmode_1486, Variable vinput_1489, Variable vinput_len_1490, ReturnStmt target_2, EqualityOperation target_3, AddressOfExpr target_4, ExprStmt target_5, AddressOfExpr target_6, ExprStmt target_7
where
not func_0(vmode_1486, vinput_1489, vinput_len_1490, target_3, target_4, target_5, target_6, target_7, func)
and func_2(func, target_2)
and func_3(vmode_1486, target_3)
and func_4(vinput_1489, target_4)
and func_5(vinput_1489, target_5)
and func_6(vinput_len_1490, target_6)
and func_7(vinput_1489, vinput_len_1490, target_7)
and vmode_1486.getType().hasName("int")
and vinput_1489.getType().hasName("char *")
and vinput_len_1490.getType().hasName("size_t")
and vmode_1486.getParentScope+() = func
and vinput_1489.getParentScope+() = func
and vinput_len_1490.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
