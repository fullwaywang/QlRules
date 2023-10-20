/**
 * @name php-921b6813da3237a83e908998483f46ae3d8bacba-sqlite_handle_quoter
 * @id cpp/php/921b6813da3237a83e908998483f46ae3d8bacba/sqlite-handle-quoter
 * @description php-921b6813da3237a83e908998483f46ae3d8bacba-ext/pdo_sqlite/sqlite_driver.c-sqlite_handle_quoter CVE-2022-31631
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vunquotedlen_233, ExprStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vunquotedlen_233
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="1073741822"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(0)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(0).getFollowingStmt()=target_0)
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vunquotedlen_233, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_safe_emalloc")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="2"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vunquotedlen_233
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="3"
}

from Function func, Parameter vunquotedlen_233, ExprStmt target_1
where
not func_0(vunquotedlen_233, target_1, func)
and func_1(vunquotedlen_233, target_1)
and vunquotedlen_233.getType().hasName("size_t")
and vunquotedlen_233.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
