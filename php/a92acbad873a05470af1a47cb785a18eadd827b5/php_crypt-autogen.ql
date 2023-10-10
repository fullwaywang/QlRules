/**
 * @name php-a92acbad873a05470af1a47cb785a18eadd827b5-php_crypt
 * @id cpp/php/a92acbad873a05470af1a47cb785a18eadd827b5/php-crypt
 * @description php-a92acbad873a05470af1a47cb785a18eadd827b5-ext/standard/crypt.c-php_crypt CVE-2023-0567
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsalt_82, BlockStmt target_2, ExprStmt target_3, LogicalAndExpr target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsalt_82
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsalt_82
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="36"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsalt_82, BlockStmt target_2, LogicalAndExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsalt_82
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="36"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsalt_82
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="50"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsalt_82
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="36"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vsalt_82, BlockStmt target_2) {
		target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getValue()="124"
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("php_crypt_blowfish_rn")
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsalt_82
		and target_2.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(SizeofExprOperator).getValue()="124"
}

predicate func_3(Parameter vsalt_82, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("php_sha256_crypt_r")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsalt_82
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="123"
}

predicate func_4(Parameter vsalt_82, LogicalAndExpr target_4) {
		target_4.getAnOperand() instanceof LogicalAndExpr
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsalt_82
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="36"
}

from Function func, Parameter vsalt_82, LogicalAndExpr target_1, BlockStmt target_2, ExprStmt target_3, LogicalAndExpr target_4
where
not func_0(vsalt_82, target_2, target_3, target_4)
and func_1(vsalt_82, target_2, target_1)
and func_2(vsalt_82, target_2)
and func_3(vsalt_82, target_3)
and func_4(vsalt_82, target_4)
and vsalt_82.getType().hasName("const char *")
and vsalt_82.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
