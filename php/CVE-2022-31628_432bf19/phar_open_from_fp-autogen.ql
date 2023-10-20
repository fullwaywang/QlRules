/**
 * @name php-432bf196d59bcb661fcf9cb7029cea9b43f490af-phar_open_from_fp
 * @id cpp/php/432bf196d59bcb661fcf9cb7029cea9b43f490af/phar-open-from-fp
 * @description php-432bf196d59bcb661fcf9cb7029cea9b43f490af-ext/phar/phar.c-phar_open_from_fp CVE-2022-31628
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vrecursion_count_1588, BlockStmt target_6, NotExpr target_7) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("char")
		and target_1.getAnOperand().(VariableAccess).getTarget()=vrecursion_count_1588
		and target_1.getParent().(IfStmt).getThen()=target_6
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getOperand().(PrefixDecrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(VariableAccess target_5, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char")
		and target_2.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(NotExpr target_8, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char")
		and target_3.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(19)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(NotExpr target_9, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char")
		and target_4.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(15)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vrecursion_count_1588, BlockStmt target_6, VariableAccess target_5) {
		target_5.getTarget()=vrecursion_count_1588
		and target_5.getParent().(IfStmt).getThen()=target_6
}

predicate func_6(BlockStmt target_6) {
		target_6.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_6.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="3"
		and target_6.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="has_zlib"
		and target_6.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(5).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_6.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("add_assoc_long_ex")
		and target_6.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="window"
		and target_6.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getValue()="6"
		and target_6.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(AddExpr).getValue()="47"
		and target_6.getStmt(1).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_6.getStmt(1).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="3"
		and target_6.getStmt(1).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="has_bz2"
		and target_6.getStmt(1).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_php_stream_seek")
		and target_6.getStmt(1).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_6.getStmt(1).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_6.getStmt(1).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("php_stream_filter_create")
}

predicate func_7(Variable vrecursion_count_1588, NotExpr target_7) {
		target_7.getOperand().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vrecursion_count_1588
}

predicate func_8(NotExpr target_8) {
		target_8.getOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_8.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="3"
}

predicate func_9(NotExpr target_9) {
		target_9.getOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_9.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="3"
}

from Function func, Variable vrecursion_count_1588, VariableAccess target_5, BlockStmt target_6, NotExpr target_7, NotExpr target_8, NotExpr target_9
where
not func_1(vrecursion_count_1588, target_6, target_7)
and not func_2(target_5, func)
and not func_3(target_8, func)
and not func_4(target_9, func)
and func_5(vrecursion_count_1588, target_6, target_5)
and func_6(target_6)
and func_7(vrecursion_count_1588, target_7)
and func_8(target_8)
and func_9(target_9)
and vrecursion_count_1588.getType().hasName("int")
and vrecursion_count_1588.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
