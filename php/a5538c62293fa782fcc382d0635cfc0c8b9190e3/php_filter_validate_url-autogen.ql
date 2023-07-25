/**
 * @name php-a5538c62293fa782fcc382d0635cfc0c8b9190e3-php_filter_validate_url
 * @id cpp/php/a5538c62293fa782fcc382d0635cfc0c8b9190e3/php-filter-validate-url
 * @description php-a5538c62293fa782fcc382d0635cfc0c8b9190e3-ext/filter/logical_filters.c-php_filter_validate_url CVE-2021-21705
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vurl_553, BlockStmt target_2, ExprStmt target_3, LogicalAndExpr target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pass"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vurl_553
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("is_userinfo_valid")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pass"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vurl_553
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vurl_553, BlockStmt target_2, LogicalAndExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="user"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vurl_553
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("is_userinfo_valid")
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="user"
		and target_1.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vurl_553
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vurl_553, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("php_url_free")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vurl_553
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("zval_ptr_dtor")
		and target_2.getStmt(2).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="134217728"
		and target_2.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_2.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
}

predicate func_3(Variable vurl_553, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("php_url_free")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vurl_553
}

from Function func, Variable vurl_553, LogicalAndExpr target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vurl_553, target_2, target_3, target_1)
and func_1(vurl_553, target_2, target_1)
and func_2(vurl_553, target_2)
and func_3(vurl_553, target_3)
and vurl_553.getType().hasName("php_url *")
and vurl_553.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
