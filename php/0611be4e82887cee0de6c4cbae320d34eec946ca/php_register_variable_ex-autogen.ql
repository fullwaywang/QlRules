/**
 * @name php-0611be4e82887cee0de6c4cbae320d34eec946ca-php_register_variable_ex
 * @id cpp/php/0611be4e82887cee0de6c4cbae320d34eec946ca/php-register-variable-ex
 * @description php-0611be4e82887cee0de6c4cbae320d34eec946ca-main/php_variables.c-php_register_variable_ex CVE-2022-31629
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvar_name_68, Parameter vval_68, Variable vvar_73, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_73
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="__Host-"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(SubExpr).getValue()="7"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_name_68
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="__Host-"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(SubExpr).getValue()="7"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zval_ptr_dtor_nogc")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vval_68
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof DoStmt
		and target_0.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_0)
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vvar_name_68, Parameter vval_68, Variable vvar_73, ExprStmt target_9, EqualityOperation target_10, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_73
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="__Secure-"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(SubExpr).getValue()="9"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_name_68
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="__Secure-"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(SubExpr).getValue()="9"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zval_ptr_dtor_nogc")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vval_68
		and target_1.getThen().(BlockStmt).getStmt(1).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_1.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_efree")
		and target_1.getThen().(BlockStmt).getStmt(2).(ReturnStmt).toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_1)
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vvar_orig_73, Variable vuse_heap_78, ExprStmt target_11, ExprStmt target_12, NotExpr target_13, NotExpr target_14, Function func) {
	exists(DoStmt target_2 |
		target_2.getCondition().(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vuse_heap_78
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_efree")
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_orig_73
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_2)
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_13.getOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getLocation())
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_14.getOperand().(NotExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vvar_orig_73, Variable vuse_heap_78, Function func, DoStmt target_4) {
		target_4.getCondition().(Literal).getValue()="0"
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vuse_heap_78
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_efree")
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_orig_73
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Function func, ReturnStmt target_5) {
		target_5.toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Parameter vvar_name_68, Variable vvar_orig_73, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_orig_73
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvar_name_68
		and target_6.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_7(Parameter vval_68, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("zval_ptr_dtor_nogc")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vval_68
}

predicate func_8(Variable vvar_73, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vvar_73
}

predicate func_9(Parameter vval_68, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("zval_ptr_dtor_nogc")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vval_68
}

predicate func_10(Variable vvar_73, EqualityOperation target_10) {
		target_10.getAnOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_10.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_73
		and target_10.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="this"
		and target_10.getAnOperand().(FunctionCall).getArgument(2).(SubExpr).getValue()="4"
		and target_10.getAnOperand().(Literal).getValue()="0"
}

predicate func_11(Variable vvar_orig_73, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("_efree")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_orig_73
}

predicate func_12(Variable vvar_orig_73, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("_efree")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_orig_73
}

predicate func_13(Variable vuse_heap_78, NotExpr target_13) {
		target_13.getOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vuse_heap_78
}

predicate func_14(Variable vuse_heap_78, NotExpr target_14) {
		target_14.getOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vuse_heap_78
}

from Function func, Parameter vvar_name_68, Parameter vval_68, Variable vvar_73, Variable vvar_orig_73, Variable vuse_heap_78, DoStmt target_4, ReturnStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, EqualityOperation target_10, ExprStmt target_11, ExprStmt target_12, NotExpr target_13, NotExpr target_14
where
not func_0(vvar_name_68, vval_68, vvar_73, target_6, target_7, target_8, func)
and not func_1(vvar_name_68, vval_68, vvar_73, target_9, target_10, func)
and not func_2(vvar_orig_73, vuse_heap_78, target_11, target_12, target_13, target_14, func)
and func_4(vvar_orig_73, vuse_heap_78, func, target_4)
and func_5(func, target_5)
and func_6(vvar_name_68, vvar_orig_73, target_6)
and func_7(vval_68, target_7)
and func_8(vvar_73, target_8)
and func_9(vval_68, target_9)
and func_10(vvar_73, target_10)
and func_11(vvar_orig_73, target_11)
and func_12(vvar_orig_73, target_12)
and func_13(vuse_heap_78, target_13)
and func_14(vuse_heap_78, target_14)
and vvar_name_68.getType().hasName("char *")
and vval_68.getType().hasName("zval *")
and vvar_73.getType().hasName("char *")
and vvar_orig_73.getType().hasName("char *")
and vuse_heap_78.getType().hasName("zend_bool")
and vvar_name_68.getParentScope+() = func
and vval_68.getParentScope+() = func
and vvar_73.getParentScope+() = func
and vvar_orig_73.getParentScope+() = func
and vuse_heap_78.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
