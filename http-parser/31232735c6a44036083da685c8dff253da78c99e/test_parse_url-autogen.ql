/**
 * @name http-parser-31232735c6a44036083da685c8dff253da78c99e-test_parse_url
 * @id cpp/http-parser/31232735c6a44036083da685c8dff253da78c99e/test-parse-url
 * @description http-parser-31232735c6a44036083da685c8dff253da78c99e-test.c-test_parse_url NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_4, Function func, DivExpr target_0) {
		target_0.getValue()="43"
		and target_0.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget().getType().hasName("unsigned int")
		and target_0.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_4
		and target_0.getEnclosingFunction() = func
}

predicate func_2(Variable vtest_3328, ExprStmt target_5, FunctionCall target_3) {
	exists(ConditionalExpr target_2 |
		target_2.getCondition().(PointerFieldAccess).getTarget().getName()="url"
		and target_2.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtest_3328
		and target_2.getThen() instanceof FunctionCall
		and target_2.getElse().(Literal).getValue()="0"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("http_parser_parse_url")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="url"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtest_3328
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof FunctionCall
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="is_connect"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtest_3328
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("http_parser_url")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vtest_3328, FunctionCall target_3) {
		target_3.getTarget().hasName("strlen")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="url"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtest_3328
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("http_parser_parse_url")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="url"
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtest_3328
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="is_connect"
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtest_3328
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("http_parser_url")
}

predicate func_4(Variable vtest_3328, BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtest_3328
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("unsigned int")
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("http_parser_url")
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="32"
}

predicate func_5(Variable vtest_3328, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("http_parser_parse_url")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="url"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtest_3328
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof FunctionCall
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="is_connect"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtest_3328
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("http_parser_url")
}

from Function func, Variable vtest_3328, DivExpr target_0, FunctionCall target_3, BlockStmt target_4, ExprStmt target_5
where
func_0(target_4, func, target_0)
and not func_2(vtest_3328, target_5, target_3)
and func_3(vtest_3328, target_3)
and func_4(vtest_3328, target_4)
and func_5(vtest_3328, target_5)
and vtest_3328.getType().hasName("const url_test *")
and vtest_3328.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
