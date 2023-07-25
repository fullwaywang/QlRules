/**
 * @name php-0e097f2c96ce31b16fa371981045f224e5a37160-php_stream_url_wrap_http_ex
 * @id cpp/php/0e097f2c96ce31b16fa371981045f224e5a37160/php-stream-url-wrap-http-ex
 * @description php-0e097f2c96ce31b16fa371981045f224e5a37160-ext/standard/http_fopen_wrapper.c-php_stream_url_wrap_http_ex CVE-2018-14884
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SubExpr target_0) {
		target_0.getValue()="14"
		and target_0.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncasecmp")
		and target_0.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Content-Length:"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, SubExpr target_1) {
		target_1.getValue()="17"
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncasecmp")
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Transfer-Encoding:"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable ve_759, Variable vhttp_header_value_760, VariableAccess target_5, LogicalAndExpr target_6, ExprStmt target_7, ExprStmt target_8) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhttp_header_value_760
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=ve_759
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_7.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_5(Variable vhttp_header_value_760, VariableAccess target_5) {
		target_5.getTarget()=vhttp_header_value_760
}

predicate func_6(Variable ve_759, Variable vhttp_header_value_760, LogicalAndExpr target_6) {
		target_6.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vhttp_header_value_760
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=ve_759
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vhttp_header_value_760
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="32"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vhttp_header_value_760
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="9"
}

predicate func_7(Variable vhttp_header_value_760, ExprStmt target_7) {
		target_7.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vhttp_header_value_760
}

predicate func_8(Variable vhttp_header_value_760, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("php_strlcpy")
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhttp_header_value_760
		and target_8.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="1024"
}

from Function func, Variable ve_759, Variable vhttp_header_value_760, SubExpr target_0, SubExpr target_1, VariableAccess target_5, LogicalAndExpr target_6, ExprStmt target_7, ExprStmt target_8
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_2(ve_759, vhttp_header_value_760, target_5, target_6, target_7, target_8)
and func_5(vhttp_header_value_760, target_5)
and func_6(ve_759, vhttp_header_value_760, target_6)
and func_7(vhttp_header_value_760, target_7)
and func_8(vhttp_header_value_760, target_8)
and ve_759.getType().hasName("char *")
and vhttp_header_value_760.getType().hasName("char *")
and ve_759.getParentScope+() = func
and vhttp_header_value_760.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
