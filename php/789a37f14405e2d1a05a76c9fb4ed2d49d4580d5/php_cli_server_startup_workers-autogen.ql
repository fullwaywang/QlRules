/**
 * @name php-789a37f14405e2d1a05a76c9fb4ed2d49d4580d5-php_cli_server_startup_workers
 * @id cpp/php/789a37f14405e2d1a05a76c9fb4ed2d49d4580d5/php-cli-server-startup-workers
 * @description php-789a37f14405e2d1a05a76c9fb4ed2d49d4580d5-sapi/cli/php_cli_server.c-php_cli_server_startup_workers CVE-2022-4900
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vphp_cli_server_workers_max, FunctionCall target_0) {
		target_0.getTarget().hasName("calloc")
		and not target_0.getTarget().hasName("__zend_calloc")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vphp_cli_server_workers_max
		and target_0.getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getArgument(1).(SizeofTypeOperator).getValue()="4"
}

predicate func_1(Variable vphp_cli_server_workers_max, Variable vphp_cli_server_workers) {
	exists(ConditionalExpr target_1 |
		target_1.getCondition() instanceof Literal
		and target_1.getThen().(FunctionCall).getTarget().hasName("__zend_calloc")
		and target_1.getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vphp_cli_server_workers_max
		and target_1.getThen().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getThen().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="4"
		and target_1.getElse().(FunctionCall).getTarget().hasName("_ecalloc")
		and target_1.getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vphp_cli_server_workers_max
		and target_1.getElse().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getElse().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="4"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vphp_cli_server_workers)
}

predicate func_3(Variable vphp_cli_server_workers_max, Variable vphp_cli_server_workers, RelationalOperation target_7, IfStmt target_3) {
		target_3.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vphp_cli_server_workers
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vphp_cli_server_workers_max
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).toString() = "return ..."
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
}

/*predicate func_4(Variable vphp_cli_server_workers_max, NotExpr target_8, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vphp_cli_server_workers_max
		and target_4.getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

*/
/*predicate func_5(NotExpr target_8, Function func, ReturnStmt target_5) {
		target_5.toString() = "return ..."
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_5.getEnclosingFunction() = func
}

*/
predicate func_7(Variable vphp_cli_server_workers_max, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vphp_cli_server_workers_max
		and target_7.getLesserOperand().(Literal).getValue()="1"
}

predicate func_8(Variable vphp_cli_server_workers, NotExpr target_8) {
		target_8.getOperand().(VariableAccess).getTarget()=vphp_cli_server_workers
}

from Function func, Variable vphp_cli_server_workers_max, Variable vphp_cli_server_workers, FunctionCall target_0, IfStmt target_3, RelationalOperation target_7, NotExpr target_8
where
func_0(vphp_cli_server_workers_max, target_0)
and not func_1(vphp_cli_server_workers_max, vphp_cli_server_workers)
and func_3(vphp_cli_server_workers_max, vphp_cli_server_workers, target_7, target_3)
and func_7(vphp_cli_server_workers_max, target_7)
and func_8(vphp_cli_server_workers, target_8)
and vphp_cli_server_workers_max.getType().hasName("zend_long")
and vphp_cli_server_workers.getType().hasName("pid_t *")
and not vphp_cli_server_workers_max.getParentScope+() = func
and not vphp_cli_server_workers.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
