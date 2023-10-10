/**
 * @name php-2d3d72412a6734e19a38ed10f385227a6238e4a6-php_url_parse_ex
 * @id cpp/php/2d3d72412a6734e19a38ed10f385227a6238e4a6/php-url-parse-ex
 * @description php-2d3d72412a6734e19a38ed10f385227a6238e4a6-ext/standard/url.c-php_url_parse_ex CVE-2020-7071
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_101, Variable vp_101, AssignExpr target_2, PointerArithmeticOperation target_3, ExprStmt target_4, PointerArithmeticOperation target_5, PointerArithmeticOperation target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("is_userinfo_valid")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_101
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_101
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vs_101
		and target_0.getThen().(BlockStmt).getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(BlockStmt).getStmt(0).(GotoStmt).getName() ="check_port"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_6.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vs_101, Variable vp_101, AssignExpr target_2) {
		target_2.getRValue().(FunctionCall).getTarget().hasName("memchr")
		and target_2.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_101
		and target_2.getRValue().(FunctionCall).getArgument(1).(CharLiteral).getValue()="58"
		and target_2.getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_101
		and target_2.getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vs_101
}

predicate func_3(Variable vs_101, PointerArithmeticOperation target_3) {
		target_3.getRightOperand().(VariableAccess).getTarget()=vs_101
}

predicate func_4(Variable vs_101, Variable vp_101, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_estrndup")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_101
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vp_101
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vs_101
}

predicate func_5(Variable vp_101, PointerArithmeticOperation target_5) {
		target_5.getLeftOperand().(VariableAccess).getTarget()=vp_101
}

predicate func_6(Variable vs_101, Variable vp_101, PointerArithmeticOperation target_6) {
		target_6.getLeftOperand().(VariableAccess).getTarget()=vp_101
		and target_6.getRightOperand().(VariableAccess).getTarget()=vs_101
}

from Function func, Variable vs_101, Variable vp_101, AssignExpr target_2, PointerArithmeticOperation target_3, ExprStmt target_4, PointerArithmeticOperation target_5, PointerArithmeticOperation target_6
where
not func_0(vs_101, vp_101, target_2, target_3, target_4, target_5, target_6)
and func_2(vs_101, vp_101, target_2)
and func_3(vs_101, target_3)
and func_4(vs_101, vp_101, target_4)
and func_5(vp_101, target_5)
and func_6(vs_101, vp_101, target_6)
and vs_101.getType().hasName("const char *")
and vp_101.getType().hasName("const char *")
and vs_101.getParentScope+() = func
and vp_101.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
